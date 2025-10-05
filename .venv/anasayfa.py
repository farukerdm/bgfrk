#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Flask tabanlı tek dosyalık uygulama (META DB: SQLite)
- Landing (/) = d1.html (hash router)
- /multiquery = PostgreSQL çoklu sorgu konsolu
- Kayıtlar SQLite meta DB'ye yazılır (dosya: PG_UI_META_SQLITE, varsayılan: mq_meta.db)
"""
import os
import sqlite3
import socket
import platform
import subprocess
from contextlib import closing
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Tuple

from flask import Flask, request, redirect, url_for, flash, jsonify, session
from flask import render_template_string, send_file

# SSH bağlantısı için paramiko
try:
    import paramiko
    PARAMIKO_AVAILABLE = True
except ImportError:
    PARAMIKO_AVAILABLE = False
    print("Paramiko kütüphanesi bulunamadı. SSH özellikleri çalışmayacak.")

# Şifreleme için cryptography
try:
    from cryptography.fernet import Fernet
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    print("Cryptography kütüphanesi bulunamadı. Şifre şifreleme özellikleri çalışmayacak.")

# ---- PostgreSQL sürücü katmanı (psycopg2 -> psycopg3 fallback) ----
try:
    import psycopg2 as _pg
    import psycopg2.extras as _pg_extras
    USING_PG2 = True
    USING_PG3 = False
except Exception:
    try:
        import psycopg as _pg
        from psycopg.rows import dict_row as _dict_row
        USING_PG2 = False
        USING_PG3 = True
    except Exception:
        _pg = None
        USING_PG2 = USING_PG3 = False

APP_TITLE = "Multiquery Module"

# --- META DB: SQLite dosya yolu (.venv içerisinde) ---
# Eğer environment variable yoksa, .venv dizini içerisinde oluştur
_default_db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mq_meta.db")
SQLITE_PATH = os.environ.get("PG_UI_META_SQLITE", _default_db_path)

MAX_ROWS = int(os.environ.get("PG_UI_MAX_ROWS", "1000"))
WORKERS = int(os.environ.get("PG_UI_WORKERS", "16"))
STMT_TIMEOUT_MS = int(os.environ.get("PG_UI_TIMEOUT_MS", "15000"))

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", "dev-secret-change-me")
app.config['JSON_AS_ASCII'] = False
app.config['TEMPLATES_AUTO_RELOAD'] = True

# Şifreleme anahtarı (güvenli bir yerde saklanmalı - production'da environment variable kullanın)
ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY", "your-secret-encryption-key-change-this-in-production")

def get_or_create_encryption_key():
    """Şifreleme anahtarını al veya oluştur"""
    # .venv dizini içerisinde encryption.key dosyasını oluştur
    current_dir = os.path.dirname(os.path.abspath(__file__))
    key_file = os.path.join(current_dir, "encryption.key")
    
    if os.path.exists(key_file):
        with open(key_file, 'rb') as f:
            return f.read()
    else:
        # Yeni anahtar oluştur
        if CRYPTO_AVAILABLE:
            key = Fernet.generate_key()
            with open(key_file, 'wb') as f:
                f.write(key)
            print(f"Şifreleme anahtarı oluşturuldu: {key_file}")
            return key
        else:
            return None

# Şifreleme anahtarını yükle
if CRYPTO_AVAILABLE:
    FERNET_KEY = get_or_create_encryption_key()
    if FERNET_KEY:
        cipher_suite = Fernet(FERNET_KEY)
    else:
        cipher_suite = None
else:
    cipher_suite = None

def encrypt_password(password: str) -> str:
    """Şifreyi şifrele"""
    if not cipher_suite or not password:
        return password
    try:
        encrypted = cipher_suite.encrypt(password.encode())
        return encrypted.decode()
    except Exception as e:
        print(f"Şifreleme hatası: {e}")
        return password

def decrypt_password(encrypted_password: str) -> str:
    """Şifreyi çöz"""
    if not cipher_suite or not encrypted_password:
        return encrypted_password
    try:
        decrypted = cipher_suite.decrypt(encrypted_password.encode())
        return decrypted.decode()
    except Exception as e:
        print(f"Şifre çözme hatası: {e}")
        return encrypted_password

# UTF-8 encoding için response handler
@app.after_request
def after_request(response):
    response.headers['Content-Type'] = 'text/html; charset=utf-8'
    return response

# pstandaloneinstall modülünü global olarak import et (performans için)
try:
    import sys
    # Mevcut dosyanın bulunduğu dizini Python path'e ekle
    current_dir = os.path.dirname(os.path.abspath(__file__))
    if current_dir not in sys.path:
        sys.path.insert(0, current_dir)
    
    import pstandaloneinstall
    PG_INSTALL_AVAILABLE = True
    print("PostgreSQL Installation modulu basariyla yuklendi")
except Exception as e:
    pstandaloneinstall = None
    PG_INSTALL_AVAILABLE = False
    print(f"PostgreSQL Installation modulu yuklenemedi: {e}")
    print(f"   Hata detayı: {type(e).__name__}: {str(e)}")
    print(f"   Mevcut dizin: {os.getcwd()}")
    print(f"   Python path: {sys.path[:3]}")

# Envanter modülü kaldırıldı

# SQLite bağlantı cache'i (performans için)
_meta_conn_cache = None
import threading
_conn_lock = threading.Lock()

# Template cache (performans için)
_template_cache = {}


# -------------------- META DB (SQLite) yardımcıları --------------------
def get_meta_conn() -> sqlite3.Connection:
    global _meta_conn_cache
    with _conn_lock:
        if _meta_conn_cache is None:
            _meta_conn_cache = sqlite3.connect(SQLITE_PATH, check_same_thread=False)
            _meta_conn_cache.row_factory = sqlite3.Row
        else:
            # Check if the connection is still valid
            try:
                _meta_conn_cache.execute("SELECT 1").fetchone()
            except sqlite3.ProgrammingError:
                # Connection is closed, create a new one
                _meta_conn_cache = sqlite3.connect(SQLITE_PATH, check_same_thread=False)
                _meta_conn_cache.row_factory = sqlite3.Row
        return _meta_conn_cache

def init_db() -> None:
    con = get_meta_conn()
    # Her tabloyu ayrı ayrı oluştur
    tables = [
            """CREATE TABLE IF NOT EXISTS servers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                host TEXT NOT NULL,
                port INTEGER NOT NULL DEFAULT 5432,
                dbname TEXT NOT NULL,
                username TEXT NOT NULL,
                password TEXT NOT NULL
            )""",
            """CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                full_name TEXT NOT NULL,
                is_admin BOOLEAN DEFAULT 0,
                is_active BOOLEAN DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP
            )""",
            """CREATE TABLE IF NOT EXISTS user_permissions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                page_name TEXT NOT NULL,
                can_access BOOLEAN DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES users (id),
                UNIQUE(user_id, page_name)
            )""",
            """CREATE TABLE IF NOT EXISTS activity_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                username TEXT NOT NULL,
                action TEXT NOT NULL,
                details TEXT,
                page_name TEXT,
                ip_address TEXT,
                user_agent TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )"""
    ]
    
    # Tabloları oluştur
    for table_sql in tables:
        con.execute(table_sql)
    
    # Eksik sütunları ekle (migration)
    try:
        # users tablosuna last_login sütunu ekle
        con.execute("ALTER TABLE users ADD COLUMN last_login TIMESTAMP")
    except sqlite3.OperationalError:
        pass  # Sütun zaten varsa hata verme
    
    try:
        # activity_logs tablosuna details sütunu ekle
        con.execute("ALTER TABLE activity_logs ADD COLUMN details TEXT")
    except sqlite3.OperationalError:
        pass  # Sütun zaten varsa hata verme
    con.commit()
    
    # Varsayılan admin kullanıcısı oluştur
    import hashlib
    admin_password = hashlib.sha256("admin123".encode()).hexdigest()
    
    # Admin kullanıcısı var mı kontrol et
    existing_admin = con.execute("SELECT id FROM users WHERE username = 'admin'").fetchone()
    if not existing_admin:
        cur = con.execute("""
            INSERT INTO users (username, password_hash, full_name, is_admin, is_active) 
            VALUES ('admin', ?, 'Faruk Erdem', 1, 1)
        """, [admin_password])
        admin_id = cur.lastrowid
        
        # Admin'e tüm sayfalara erişim ver
        pages = ['multiquery', 'pg_install', 'admin_panel', 'faydali_linkler', 'view_logs', 'envanter', 'healthcheck']
        for page in pages:
            con.execute("""
                INSERT INTO user_permissions (user_id, page_name, can_access) 
                VALUES (?, ?, 1)
            """, [admin_id, page])
        
        con.commit()
    
    # Mevcut admin kullanıcısına healthcheck yetkisi ekle (migration)
    try:
        admin_users = con.execute("SELECT id FROM users WHERE is_admin = 1").fetchall()
        for admin_user in admin_users:
            admin_id = admin_user[0]
            # Healthcheck yetkisi var mı kontrol et
            existing_perm = con.execute("""
                SELECT id FROM user_permissions 
                WHERE user_id = ? AND page_name = 'healthcheck'
            """, [admin_id]).fetchone()
            
            if not existing_perm:
                con.execute("""
                    INSERT INTO user_permissions (user_id, page_name, can_access)
                    VALUES (?, 'healthcheck', 1)
                """, [admin_id])
        con.commit()
    except:
        pass  # Hata olursa devam et

def db_query(sql: str, args: Tuple = ()) -> List[Dict[str, Any]]:
    try:
        con = get_meta_conn()
        cur = con.execute(sql, args)
        rows = [dict(row) for row in cur.fetchall()]
        return rows
    except sqlite3.ProgrammingError:
        # Connection might be closed, try to get a fresh connection
        with _conn_lock:
            global _meta_conn_cache
            _meta_conn_cache = None
            con = get_meta_conn()
            cur = con.execute(sql, args)
            rows = [dict(row) for row in cur.fetchall()]
            return rows

def db_execute(sql: str, args: Tuple = ()) -> int:
    try:
        con = get_meta_conn()
        cur = con.execute(sql, args)
        con.commit()
        return cur.rowcount
    except sqlite3.ProgrammingError:
        with _conn_lock:
            global _meta_conn_cache
            _meta_conn_cache = None
            con = get_meta_conn()
            cur = con.execute(sql, args)
            con.commit()
            return cur.rowcount

def init_sunucu_envanteri_table():
    """Sunucu envanteri tablosunu oluştur"""
    try:
        db_execute("""
            CREATE TABLE IF NOT EXISTS sunucu_envanteri (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hostname TEXT NOT NULL,
                ip TEXT NOT NULL,
                ssh_port INTEGER DEFAULT 22,
                ssh_user TEXT,
                ssh_password TEXT,
                os_info TEXT,
                cpu_info TEXT,
                cpu_cores TEXT,
                ram_total TEXT,
                disks TEXT,
                uptime TEXT,
                postgresql_status TEXT,
                postgresql_version TEXT,
                postgresql_replication TEXT,
                pgbackrest_status TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Mevcut tabloya ssh_password sütunu ekle (eğer yoksa)
        try:
            db_execute("ALTER TABLE sunucu_envanteri ADD COLUMN ssh_password TEXT")
            print("ssh_password sütunu eklendi.")
        except:
            pass  # Sütun zaten varsa hata vermez
            
    except Exception as e:
        print(f"Sunucu envanteri tablosu oluşturulurken hata: {e}")

def init_healthcheck_table():
    """Healthcheck sonuçları tablosunu oluştur"""
    try:
        db_execute("""
            CREATE TABLE IF NOT EXISTS healthcheck_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                server_id INTEGER NOT NULL,
                hostname TEXT NOT NULL,
                ip TEXT NOT NULL,
                status TEXT NOT NULL,
                os_info TEXT,
                cpu_info TEXT,
                cpu_cores TEXT,
                ram_total TEXT,
                ram_used TEXT,
                ram_free TEXT,
                disks TEXT,
                uptime TEXT,
                postgresql_status TEXT,
                postgresql_version TEXT,
                postgresql_replication TEXT,
                pgbackrest_status TEXT,
                network_info TEXT,
                load_average TEXT,
                kernel_version TEXT,
                architecture TEXT,
                last_boot TEXT,
                swap_memory TEXT,
                memory_detailed TEXT,
                top_cpu_processes TEXT,
                top_memory_processes TEXT,
                disk_io_stats TEXT,
                network_interfaces TEXT,
                dns_servers TEXT,
                timezone TEXT,
                running_services TEXT,
                failed_services TEXT,
                listening_ports TEXT,
                total_connections TEXT,
                pg_connection_count TEXT,
                pg_max_connections TEXT,
                pg_databases TEXT,
                pg_total_size TEXT,
                pg_data_directory TEXT,
                pg_port TEXT,
                pg_shared_buffers TEXT,
                pg_work_mem TEXT,
                pg_effective_cache_size TEXT,
                pg_maintenance_work_mem TEXT,
                pg_wal_level TEXT,
                pg_archive_mode TEXT,
                pg_replication_slots TEXT,
                pg_uptime TEXT,
                error_message TEXT,
                checked_by INTEGER NOT NULL,
                checked_by_username TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (server_id) REFERENCES sunucu_envanteri (id),
                FOREIGN KEY (checked_by) REFERENCES users (id)
            )
        """)
        print("healthcheck_results tablosu oluşturuldu.")
        
        # Tüm eksik sütunları ekle (eğer yoksa) - tek tek kontrol edelim
        migration_columns = [
            ('kernel_version', 'TEXT'),
            ('architecture', 'TEXT'),
            ('last_boot', 'TEXT'),
            ('swap_memory', 'TEXT'),
            ('memory_detailed', 'TEXT'),
            ('top_cpu_processes', 'TEXT'),
            ('top_memory_processes', 'TEXT'),
            ('disk_io_stats', 'TEXT'),
            ('network_interfaces', 'TEXT'),
            ('dns_servers', 'TEXT'),
            ('timezone', 'TEXT'),
            ('running_services', 'TEXT'),
            ('failed_services', 'TEXT'),
            ('listening_ports', 'TEXT'),
            ('total_connections', 'TEXT'),
            ('kernel_params', 'TEXT'),
            ('kernel_params_summary', 'TEXT'),
            ('pg_connection_count', 'TEXT'),
            ('pg_max_connections', 'TEXT'),
            ('pg_databases', 'TEXT'),
            ('pg_total_size', 'TEXT'),
            ('pg_data_directory', 'TEXT'),
            ('pg_port', 'TEXT'),
            ('pg_shared_buffers', 'TEXT'),
            ('pg_work_mem', 'TEXT'),
            ('pg_effective_cache_size', 'TEXT'),
            ('pg_maintenance_work_mem', 'TEXT'),
            ('pg_wal_level', 'TEXT'),
            ('pg_archive_mode', 'TEXT'),
            ('pg_replication_slots', 'TEXT'),
            ('pg_uptime', 'TEXT'),
            ('system_update_status', 'TEXT'),
            ('system_update_message', 'TEXT'),
            ('pgbackrest_details', 'TEXT'),
            ('pg_probackup_status', 'TEXT'),
            ('pg_probackup_path', 'TEXT'),
            ('pg_probackup_details', 'TEXT'),
            ('pgbarman_status', 'TEXT'),
            ('pgbarman_details', 'TEXT'),
            ('backup_info', 'TEXT'),
            ('disk_type', 'TEXT'),
            ('disk_write_speed', 'TEXT'),
            ('disk_read_speed', 'TEXT'),
            ('disk_performance_test', 'TEXT'),
            ('patroni_status', 'TEXT'),
            ('patroni_details', 'TEXT'),
            ('repmgr_status', 'TEXT'),
            ('repmgr_details', 'TEXT'),
            ('paf_status', 'TEXT'),
            ('paf_details', 'TEXT'),
            ('citus_status', 'TEXT'),
            ('citus_details', 'TEXT'),
            ('streaming_replication_status', 'TEXT'),
            ('streaming_replication_details', 'TEXT'),
            ('ha_tools_summary', 'TEXT'),
            ('cpu_details', 'TEXT'),
        ]
        
        for col_name, col_type in migration_columns:
            try:
                db_execute(f"ALTER TABLE healthcheck_results ADD COLUMN {col_name} {col_type}")
                print(f"{col_name} sütunu eklendi.")
            except:
                pass  # Sütun zaten varsa hata vermez
        
        # Tüm migration'lar yukarıda yapılıyor artık
            
    except Exception as e:
        print(f"Healthcheck tablosu oluşturulurken hata: {e}")

def save_sunucu_bilgileri(server_info):
    """Sunucu bilgilerini veritabanına kaydet (varsa güncelle, yoksa ekle)"""
    try:
        # Disks bilgisini JSON string'e çevir
        import json
        disks_json = json.dumps(server_info.get('disks', []))
        
        # Şifreyi şifrele (eğer varsa)
        encrypted_password = None
        if server_info.get('ssh_password'):
            encrypted_password = encrypt_password(server_info.get('ssh_password'))
        
        # Önce aynı IP'ye sahip sunucu var mı kontrol et (sadece IP bazında duplicate kontrol)
        existing_server = db_query("""
            SELECT * FROM sunucu_envanteri 
            WHERE ip = ?
        """, (server_info.get('ip', ''),))
        
        if existing_server:
            existing = existing_server[0]
            
            # Eksik bilgileri kontrol et ve değişiklik var mı bak
            has_changes = False
            changes = []
            
            # Her alanı kontrol et
            fields_to_check = {
                'os_info': server_info.get('os_info', 'N/A'),
                'cpu_info': server_info.get('cpu_info', 'N/A'),
                'cpu_cores': server_info.get('cpu_cores', 'N/A'),
                'ram_total': server_info.get('ram_total', 'N/A'),
                'disks': disks_json,
                'uptime': server_info.get('uptime', 'N/A'),
                'postgresql_status': server_info.get('postgresql_status', 'Yok'),
                'postgresql_version': server_info.get('postgresql_version', 'N/A'),
                'postgresql_replication': server_info.get('postgresql_replication', 'N/A'),
                'pgbackrest_status': server_info.get('pgbackrest_status', 'Yok')
            }
            
            for field, new_value in fields_to_check.items():
                old_value = existing.get(field, 'N/A')
                
                # Eksik bilgi kontrolü (N/A veya boş ise eksik kabul et)
                if old_value in ['N/A', '', None] and new_value not in ['N/A', '', None]:
                    has_changes = True
                    changes.append(f"{field}: eksik bilgi eklendi")
                # Değişiklik kontrolü
                elif old_value != new_value and new_value not in ['N/A', '', None]:
                    has_changes = True
                    changes.append(f"{field}: güncellendi")
            
            if has_changes:
                # Değişiklik varsa güncelle
                db_execute("""
                    UPDATE sunucu_envanteri SET
                        hostname = ?, ip = ?, ssh_port = ?, ssh_user = ?, ssh_password = ?,
                        os_info = ?, cpu_info = ?, cpu_cores = ?, ram_total = ?, 
                        disks = ?, uptime = ?, postgresql_status = ?, 
                        postgresql_version = ?, postgresql_replication = ?, 
                        pgbackrest_status = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                """, (
                    server_info.get('hostname', ''),
                    server_info.get('ip', ''),
                    server_info.get('ssh_port', 22),
                    server_info.get('ssh_user', ''),
                    encrypted_password,
                    server_info.get('os_info', 'N/A'),
                    server_info.get('cpu_info', 'N/A'),
                    server_info.get('cpu_cores', 'N/A'),
                    server_info.get('ram_total', 'N/A'),
                    disks_json,
                    server_info.get('uptime', 'N/A'),
                    server_info.get('postgresql_status', 'Yok'),
                    server_info.get('postgresql_version', 'N/A'),
                    server_info.get('postgresql_replication', 'N/A'),
                    server_info.get('pgbackrest_status', 'Yok'),
                    existing['id']
                ))
                change_details = ", ".join(changes[:3])  # İlk 3 değişikliği göster
                if len(changes) > 3:
                    change_details += f" ve {len(changes)-3} alan daha"
                return True, f"güncellendi ({change_details})"
            else:
                # Değişiklik yoksa duplicate uyarısı
                return False, "Bu kayıt zaten mevcut ve değiştirilecek bilgi yok (duplicate kayıt)"
        else:
            # Yoksa ekle
            db_execute("""
                INSERT INTO sunucu_envanteri 
                (hostname, ip, ssh_port, ssh_user, ssh_password, os_info, cpu_info, cpu_cores, 
                 ram_total, disks, uptime, postgresql_status, postgresql_version, 
                 postgresql_replication, pgbackrest_status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                server_info.get('hostname', ''),
                server_info.get('ip', ''),
                server_info.get('ssh_port', 22),
                server_info.get('ssh_user', ''),
                encrypted_password,
                server_info.get('os_info', 'N/A'),
                server_info.get('cpu_info', 'N/A'),
                server_info.get('cpu_cores', 'N/A'),
                server_info.get('ram_total', 'N/A'),
                disks_json,
                server_info.get('uptime', 'N/A'),
                server_info.get('postgresql_status', 'Yok'),
                server_info.get('postgresql_version', 'N/A'),
                server_info.get('postgresql_replication', 'N/A'),
                server_info.get('pgbackrest_status', 'Yok')
            ))
            return True, "eklendi"
    except Exception as e:
        print(f"Sunucu bilgileri kaydedilirken hata: {e}")
        return False, str(e)

def clean_duplicate_servers():
    """Duplicate sunucu kayıtlarını temizle (IP bazında)"""
    try:
        # Aynı IP'ye sahip duplicate kayıtları bul
        duplicates = db_query("""
            SELECT ip, COUNT(*) as count, GROUP_CONCAT(id) as ids, GROUP_CONCAT(hostname) as hostnames
            FROM sunucu_envanteri 
            GROUP BY ip 
            HAVING COUNT(*) > 1
        """)
        
        cleaned_count = 0
        for duplicate in duplicates:
            ids = duplicate['ids'].split(',')
            ids = [int(id.strip()) for id in ids]
            
            # En son güncellenen kaydı tut, diğerlerini sil
            keep_id = None
            latest_updated = None
            
            for server_id in ids:
                server_info = db_query("SELECT id, updated_at FROM sunucu_envanteri WHERE id = ?", (server_id,))
                if server_info:
                    updated_at = server_info[0]['updated_at']
                    if latest_updated is None or updated_at > latest_updated:
                        latest_updated = updated_at
                        keep_id = server_id
            
            # Diğer duplicate kayıtları sil
            for server_id in ids:
                if server_id != keep_id:
                    db_execute("DELETE FROM sunucu_envanteri WHERE id = ?", (server_id,))
                    cleaned_count += 1
            
            hostnames = duplicate['hostnames'].split(',')
            hostnames = [h.strip() for h in hostnames]
            print(f"Duplicate temizlendi: IP {duplicate['ip']} - Hostname'ler: {', '.join(hostnames)} - {len(ids)-1} kayıt silindi")
        
        return cleaned_count
    except Exception as e:
        print(f"Duplicate temizleme hatası: {e}")
        return 0

# Kimlik doğrulama fonksiyonları
def hash_password(password: str) -> str:
    import hashlib
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(password: str, password_hash: str) -> bool:
    return hash_password(password) == password_hash

def authenticate_user(username: str, password: str) -> dict:
    users = db_query("SELECT * FROM users WHERE username = ? AND is_active = 1", [username])
    if not users:
        return None
    
    user = users[0]
    if verify_password(password, user['password_hash']):
        return dict(user)
    return None

def check_permission(user_id: int, page_name: str) -> bool:
    # Admin kullanıcılar her şeye erişebilir
    user = db_query("SELECT is_admin FROM users WHERE id = ?", [user_id])
    if user and user[0]['is_admin']:
        return True
    
    # Normal kullanıcılar için yetki kontrolü
    permissions = db_query(
        "SELECT can_access FROM user_permissions WHERE user_id = ? AND page_name = ?", 
        [user_id, page_name]
    )
    return permissions and permissions[0]['can_access']

# Jinja2 template'lerinde kullanılabilir global fonksiyonları ekle
app.jinja_env.globals.update(
    check_permission=check_permission,
    min=min,
    max=max,
    len=len
)

def log_activity(user_id: int, username: str, action: str, details: str = "", page_name: str = None):
    from flask import request
    
    # IP adresini al
    ip_address = request.remote_addr if request else "unknown"
    
    # User agent'ı al
    user_agent = request.headers.get('User-Agent', 'unknown') if request else "unknown"
    
    # Sayfa isimlerini Türkçe'ye çevir
    page_names_tr = {
        'multiquery': 'Multiquery (SQL Sorgu Konsolu)',
        'pg_install': 'PostgreSQL Kurulum',
        'admin_panel': 'Admin Panel (Kullanıcı Yönetimi)',
        'faydali_linkler': 'Faydalı Linkler',
        'view_logs': 'Aktivite Logları',
        'envanter': 'Sunucu Envanteri',
        'manuel-sunucu-ekle': 'Manuel Sunucu Ekleme',
        'toplu-sunucu-ekle': 'Toplu Sunucu Ekleme',
        'sunuculari-listele': 'Sunucuları Listele',
        'sunucu-excel-export': 'Excel Export',
        'envantere-ekle': 'Envantere Ekleme',
        'landing': 'Ana Sayfa',
        'login': 'Giriş Sayfası',
        'logout': 'Çıkış İşlemi'
    }
    
    # Action'ları Türkçe ve detaylı hale getir
    action_messages = {
        'login': '🔐 Giriş yaptı',
        'logout': '🚪 Çıkış yaptı',
        'add_user': '👤 Yeni kullanıcı ekledi',
        'edit_user': '✏️ Kullanıcı bilgilerini düzenledi',
        'delete_user': '🗑️ Kullanıcıyı sildi',
        'toggle_user': '🔄 Kullanıcı durumunu değiştirdi',
        'manage_permissions': '🔑 Kullanıcı yetkilerini düzenledi',
        'run_query': '📊 SQL sorgusu çalıştırdı',
        'add_server': '🖥️ Sunucu ekledi',
        'edit_server': '⚙️ Sunucu bilgilerini düzenledi',
        'delete_server': '🗑️ Sunucuyu sildi',
        'export_csv': '📄 CSV dosyası export etti',
        'export_zip': '📦 ZIP dosyası export etti',
        'pg_install': '🐘 PostgreSQL kurulum işlemi başlattı',
        'access_denied': '🚫 Yetkisi olmayan sayfaya erişim denedi',
        'page_access': '📱 Sayfa ziyaret etti',
        'view_logs': '📋 Aktivite loglarını görüntüledi',
        'export_logs': '📊 Log dosyası export etti',
        'server_test': '🔍 Sunucu bağlantısını test etti',
        'query_error': '❌ SQL sorgu hatası',
        'query_success': '✅ SQL sorgu başarılı',
        'system_start': '🚀 Sistem başlatıldı',
        'system_stop': '⏹️ Sistem durduruldu',
        'envanter_access': '📋 Envanter sayfasını ziyaret etti',
        'manuel_server_add': '🖥️ Manuel sunucu ekleme sayfasını ziyaret etti',
        'bulk_server_add': '📊 Toplu sunucu ekleme sayfasını ziyaret etti',
        'server_list': '📋 Sunucu listesi sayfasını ziyaret etti',
        'server_scan': '🔍 Sunucu tarama işlemi yaptı',
        'server_add_to_inventory': '📋 Sunucuyu envantere ekledi',
        'excel_export': '📊 Excel export işlemi yaptı',
        'bulk_server_scan': '🔍 Toplu sunucu tarama işlemi yaptı',
        'form_submit': '📝 Form gönderdi',
        'file_upload': '📁 Dosya yükledi',
        'data_export': '📊 Veri export etti',
        'data_import': '📥 Veri import etti',
        'search_performed': '🔍 Arama yaptı',
        'filter_applied': '🔍 Filtre uyguladı',
        'settings_changed': '⚙️ Ayar değiştirdi',
        'theme_changed': '🎨 Tema değiştirdi'
    }
    
    # Sayfa ziyaret etme durumunda özel mesaj oluştur
    if action == 'page_access' and page_name:
        page_display_name = page_names_tr.get(page_name, page_name)
        action_message = f"📱 {page_display_name} sayfasını ziyaret etti"
    else:
        action_message = action_messages.get(action, action)
    
    # Detaylı log mesajı oluştur
    log_details = f"{action_message}"
    if details:
        log_details += f" - {details}"
    elif page_name and action != 'page_access':
        page_display_name = page_names_tr.get(page_name, page_name)
        log_details += f" - Sayfa: {page_display_name}"
    
    # IP adresini kısalt (güvenlik için)
    short_ip = ip_address[:15] + "..." if len(ip_address) > 15 else ip_address
    
    # User agent'ı kısalt
    short_ua = user_agent[:50] + "..." if len(user_agent) > 50 else user_agent
    
    try:
        db_execute("""
            INSERT INTO activity_logs (user_id, username, action, details, page_name, ip_address, user_agent, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))
        """, [user_id, username, log_details, details, page_name, short_ip, short_ua])
    except Exception as e:
        print(f"Log yazma hatası: {e}")

def log_sql_query(user_id: int, username: str, sql_query: str, servers: list, results: dict, page_name: str = "multiquery"):
    """SQL sorguları için özel detaylı logging"""
    from flask import request
    
    # IP adresini al
    ip_address = request.remote_addr if request else "unknown"
    user_agent = request.headers.get('User-Agent', 'unknown') if request else "unknown"
    
    # Sunucu bilgilerini hazırla
    server_names = [f"{s['name']} ({s['host']}:{s['port']})" for s in servers]
    server_list = ", ".join(server_names)
    
    # Sorgu uzunluğunu kontrol et
    query_preview = sql_query[:100] + "..." if len(sql_query) > 100 else sql_query
    
    # Sonuç bilgilerini hazırla
    total_rows = sum(len(r.get('rows', [])) for r in results if r.get('ok'))
    success_count = sum(1 for r in results if r.get('ok'))
    error_count = len(results) - success_count
    
    # Detaylı mesaj oluştur
    details = f"Sunucular: {server_list} | Başarılı: {success_count}/{len(results)} | Toplam satır: {total_rows}"
    if error_count > 0:
        details += f" | Hatalı: {error_count}"
    
    # Action mesajını sorgu ile birleştir
    action_message = f"📊 Şu sorguyu çalıştırdı: '{query_preview}'"
    
    # IP ve User Agent'ı kısalt
    short_ip = ip_address[:15] + "..." if len(ip_address) > 15 else ip_address
    short_ua = user_agent[:50] + "..." if len(user_agent) > 50 else user_agent
    
    try:
        db_execute("""
            INSERT INTO activity_logs (user_id, username, action, details, page_name, ip_address, user_agent, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))
        """, [user_id, username, action_message, details, page_name, short_ip, short_ua])
    except Exception as e:
        print(f"SQL log yazma hatası: {e}")

def log_server_operation(user_id: int, username: str, operation: str, server_info: dict, success: bool = True, error_msg: str = ""):
    """Sunucu işlemleri için özel logging"""
    from flask import request
    
    ip_address = request.remote_addr if request else "unknown"
    user_agent = request.headers.get('User-Agent', 'unknown') if request else "unknown"
    
    # Sunucu bilgilerini hazırla
    server_desc = f"{server_info.get('name', 'Bilinmeyen')} ({server_info.get('host', 'N/A')}:{server_info.get('port', 'N/A')})"
    
    # İşlem mesajları
    operation_messages = {
        'add': '🖥️ Sunucu ekledi',
        'edit': '⚙️ Sunucu bilgilerini düzenledi',
        'delete': '🗑️ Sunucuyu sildi',
        'test': '🔍 Sunucu bağlantısını test etti'
    }
    
    action_message = operation_messages.get(operation, f"🖥️ Sunucu işlemi: {operation}")
    
    # Detaylı mesaj
    details = f"Sunucu: {server_desc}"
    if not success and error_msg:
        details += f" | Hata: {error_msg}"
    elif success:
        details += " | Başarılı"
    
    # IP ve User Agent'ı kısalt
    short_ip = ip_address[:15] + "..." if len(ip_address) > 15 else ip_address
    short_ua = user_agent[:50] + "..." if len(user_agent) > 50 else user_agent
    
    try:
        db_execute("""
            INSERT INTO activity_logs (user_id, username, action, details, page_name, ip_address, user_agent, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))
        """, [user_id, username, action_message, details, "multiquery", short_ip, short_ua])
    except Exception as e:
        print(f"Sunucu log yazma hatası: {e}")

# Yetkilendirme decorator'ı
def require_auth(page_name: str = None):
    def decorator(f):
        def decorated_function(*args, **kwargs):
            # Giriş yapmış mı kontrol et
            if 'user_id' not in session:
                return redirect(url_for('login'))
            
            # Sayfa yetkisi kontrol et
            if page_name and not check_permission(session['user_id'], page_name):
                log_activity(session['user_id'], session['username'], 'access_denied', 
                            f'Yetkisi olmayan sayfaya erişim denedi: {page_name}', page_name)
                flash("Yetkiniz yok! Faruk Erdem'e tatlı ısmarlayın 😊", "danger")
                return redirect(url_for('landing'))
            
            # Aktiviteyi logla
            log_activity(session['user_id'], session['username'], 'page_access', page_name)
            
            return f(*args, **kwargs)
        decorated_function.__name__ = f.__name__
        return decorated_function
    return decorator

def db_insert_server(name: str, host: str, port: int, dbname: str, username: str, password: str) -> int:
    sql = "INSERT INTO servers (name, host, port, dbname, username, password) VALUES (?, ?, ?, ?, ?, ?)"
    with closing(get_meta_conn()) as con:
        cur = con.execute(sql, (name, host, port, dbname, username, password))
        con.commit()
        return int(cur.lastrowid)

def _ensure_pg_driver():
    if not _pg:
        raise RuntimeError("PostgreSQL sürücüsü yok. 'pip install psycopg2-binary' veya 'pip install psycopg[binary]' kurun.")

def _ensure_ssh_driver():
    if not PARAMIKO_AVAILABLE:
        raise RuntimeError("SSH sürücüsü yok. 'pip install paramiko' kurun.")

def collect_server_info(hostname, ip, ssh_port, ssh_user, password):
    """SSH ile sunucuya bağlanarak sistem bilgilerini toplar"""
    _ensure_ssh_driver()
    
    server_info = {
        'hostname': hostname,
        'ip': ip,
        'ssh_port': ssh_port,
        'ssh_user': ssh_user,
        'ssh_password': password,  # Şifreyi de kaydet
        'os_info': 'N/A',
        'cpu_info': 'N/A',
        'cpu_cores': 'N/A',
        'ram_total': 'N/A',
        'disks': 'N/A',
        'uptime': 'N/A',
        'postgresql_status': 'Yok',
        'postgresql_version': 'N/A',
        'postgresql_replication': 'N/A',
        'pgbackrest_status': 'Yok'
    }
    
    try:
        # SSH bağlantısı oluştur
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname=ip, port=int(ssh_port), username=ssh_user, password=password, timeout=10)
        
        # İşletim sistemi bilgisi
        try:
            stdin, stdout, stderr = ssh.exec_command("cat /etc/os-release | grep PRETTY_NAME | cut -d'=' -f2 | tr -d '\"'")
            os_info = stdout.read().decode().strip()
            if not os_info:
                # Alternatif yöntem
                stdin, stdout, stderr = ssh.exec_command("uname -a")
                os_info = stdout.read().decode().strip()
            if os_info:
                server_info['os_info'] = os_info
        except:
            pass
        
        # CPU bilgisi, cores ve sockets - Geliştirilmiş
        try:
            # CPU model bilgisini al
            stdin, stdout, stderr = ssh.exec_command("cat /proc/cpuinfo | grep 'model name' | head -1 | cut -d':' -f2 | xargs")
            cpu_model = stdout.read().decode().strip()
            
            # Toplam core sayısını al (logical cores)
            stdin, stdout, stderr = ssh.exec_command("nproc")
            total_cores = stdout.read().decode().strip()
            
            # Physical core sayısını al
            stdin, stdout, stderr = ssh.exec_command("grep 'cpu cores' /proc/cpuinfo | head -1 | cut -d':' -f2 | xargs")
            physical_cores = stdout.read().decode().strip()
            
            # Socket sayısını al (fiziksel CPU sayısı)
            stdin, stdout, stderr = ssh.exec_command("grep 'physical id' /proc/cpuinfo | sort -u | wc -l")
            sockets = stdout.read().decode().strip()
            
            # Hyperthreading kontrolü
            hyperthreading = "Yes" if (total_cores and physical_cores and int(total_cores) > int(physical_cores)) else "No"
            
            # CPU bilgisini birleştir
            if cpu_model and total_cores:
                server_info['cpu_info'] = f"{cpu_model} ({total_cores} cores)"
                server_info['cpu_cores'] = f"{total_cores} cores"
                
                # Socket ve core detaylarını hazırla
                cpu_details = []
                if sockets and int(sockets) > 0:
                    cpu_details.append(f"{sockets} socket(s)")
                if physical_cores and total_cores:
                    if int(physical_cores) < int(total_cores):
                        cpu_details.append(f"{physical_cores} physical cores")
                        cpu_details.append(f"{total_cores} logical cores")
                    else:
                        cpu_details.append(f"{total_cores} cores")
                if hyperthreading == "Yes":
                    cpu_details.append("HT enabled")
                
                server_info['cpu_details'] = " | ".join(cpu_details) if cpu_details else f"{total_cores} cores"
            elif cpu_model:
                server_info['cpu_info'] = cpu_model
                server_info['cpu_cores'] = 'N/A'
                server_info['cpu_details'] = 'N/A'
            elif total_cores:
                server_info['cpu_info'] = f"CPU ({total_cores} cores)"
                server_info['cpu_cores'] = f"{total_cores} cores"
                server_info['cpu_details'] = f"{total_cores} cores"
            else:
                server_info['cpu_info'] = 'N/A'
                server_info['cpu_cores'] = 'N/A'
                server_info['cpu_details'] = 'N/A'
        except:
            server_info['cpu_info'] = 'N/A'
            server_info['cpu_cores'] = 'N/A'
            server_info['cpu_details'] = 'N/A'
        
        # RAM bilgisi
        try:
            stdin, stdout, stderr = ssh.exec_command("free -h | grep 'Mem:' | awk '{print $2}'")
            ram_info = stdout.read().decode().strip()
            if ram_info:
                server_info['ram_total'] = ram_info
        except:
            pass
        
        # Disk bilgisi - basit ve uyumlu format
        try:
            # Basit df komutu
            stdin, stdout, stderr = ssh.exec_command("df -h")
            disk_output = stdout.read().decode().strip()
            stderr_output = stderr.read().decode().strip()
            
            print(f"Disk komut çıktısı:\n{disk_output}")
            if stderr_output:
                print(f"Disk komut hatası: {stderr_output}")
            
            if disk_output:
                disks = []
                lines = disk_output.split('\n')
                
                for line in lines[1:]:  # İlk satırı (başlık) atla
                    if line.strip() and not any(skip in line.lower() for skip in ['tmpfs', 'udev', 'devtmpfs', 'overlay']):
                        # Satırı boşluklara göre böl
                        parts = line.split()
                        if len(parts) >= 6:
                            device = parts[0]
                            size = parts[1]
                            used = parts[2]
                            available = parts[3]
                            percent = parts[4]
                            mount = parts[5]
                            
                            print(f"Disk bulundu: {device} -> {mount} ({percent})")
                            
                            # Geçerli disk kontrolü
                            if device and mount and mount.startswith('/'):
                                disks.append({
                                    'device': device,
                                    'size': size,
                                    'used': used,
                                    'available': available,
                                    'percent': percent,
                                    'mount': mount,
                                    'percent_num': int(percent.replace('%', '')) if percent.replace('%', '').isdigit() else 0
                                })
                
                print(f"Toplam {len(disks)} disk bulundu")
                server_info['disks'] = disks
            else:
                print("Disk bilgisi alınamadı")
                server_info['disks'] = []
        except Exception as e:
            print(f"Disk bilgisi toplama hatası: {e}")
            server_info['disks'] = []
        
        # Uptime bilgisi
        try:
            stdin, stdout, stderr = ssh.exec_command("uptime -p")
            uptime_info = stdout.read().decode().strip()
            if uptime_info:
                server_info['uptime'] = uptime_info
        except:
            pass
        
        # PostgreSQL durumu - birden fazla yöntem dene
        try:
            # Yöntem 1: systemctl ile servis durumu
            stdin, stdout, stderr = ssh.exec_command("systemctl is-active postgresql 2>/dev/null || systemctl is-active postgresql@* 2>/dev/null || systemctl is-active postgresql-* 2>/dev/null")
            pg_status = stdout.read().decode().strip()
            
            # Yöntem 2: Eğer systemctl çalışmazsa, ps ile process kontrolü
            if not pg_status or pg_status not in ['active', 'running']:
                stdin, stdout, stderr = ssh.exec_command("ps aux | grep -v grep | grep postgres | wc -l")
                process_count = stdout.read().decode().strip()
                if process_count and int(process_count) > 0:
                    pg_status = 'active'
            
            # Yöntem 3: pg_ctl ile status kontrolü
            if not pg_status or pg_status not in ['active', 'running']:
                stdin, stdout, stderr = ssh.exec_command("pg_ctl status -D /var/lib/postgresql/*/main 2>/dev/null | head -1")
                pg_status = stdout.read().decode().strip()
            
            # Yöntem 4: Port kontrolü
            if not pg_status or pg_status not in ['active', 'running']:
                stdin, stdout, stderr = ssh.exec_command("netstat -tlnp | grep :5432 | wc -l")
                port_count = stdout.read().decode().strip()
                if port_count and int(port_count) > 0:
                    pg_status = 'active'
            
            if pg_status and ('active' in pg_status.lower() or 'running' in pg_status.lower() or pg_status == 'active'):
                server_info['postgresql_status'] = 'Var'
                
                # PostgreSQL server versiyonu - birden fazla yöntem dene
                try:
                    # Yöntem 1: psql --version (doesn't require sudo)
                    stdin, stdout, stderr = ssh.exec_command("psql --version 2>/dev/null")
                    pg_version = stdout.read().decode().strip()
                    
                    # Yöntem 2: pg_config --version
                    if not pg_version or 'PostgreSQL' not in pg_version:
                        stdin, stdout, stderr = ssh.exec_command("pg_config --version 2>/dev/null")
                        pg_version = stdout.read().decode().strip()
                    
                    # Yöntem 3: PostgreSQL server versiyonu (with sudo)
                    if not pg_version or 'PostgreSQL' not in pg_version:
                        stdin, stdout, stderr = ssh.exec_command("sudo -n -u postgres psql -t -c 'SELECT version();' 2>/dev/null")
                        pg_version = stdout.read().decode().strip()
                    
                    # Yöntem 4: postgres server binary versiyonu
                    if not pg_version or 'PostgreSQL' not in pg_version:
                        stdin, stdout, stderr = ssh.exec_command("sudo -n -u postgres postgres --version 2>/dev/null")
                        pg_version = stdout.read().decode().strip()
                    
                    # Yöntem 3: Eğer hala çalışmazsa, pg_config ile versiyon
                    if not pg_version or 'PostgreSQL' not in pg_version:
                        stdin, stdout, stderr = ssh.exec_command("pg_config --version 2>/dev/null")
                        pg_version = stdout.read().decode().strip()
                        if pg_version:
                            pg_version = f"PostgreSQL {pg_version}"
                    
                    # Yöntem 4: systemctl ile servis versiyonu
                    if not pg_version or 'PostgreSQL' not in pg_version:
                        stdin, stdout, stderr = ssh.exec_command("systemctl show postgresql -p Version 2>/dev/null | cut -d'=' -f2")
                        pg_version = stdout.read().decode().strip()
                        if pg_version:
                            pg_version = f"PostgreSQL {pg_version}"
                    
                    # Yöntem 5: paket yöneticisi ile kurulu server versiyonu
                    if not pg_version or 'PostgreSQL' not in pg_version:
                        stdin, stdout, stderr = ssh.exec_command("rpm -q postgresql-server 2>/dev/null | head -1")
                        pg_version = stdout.read().decode().strip()
                        if not pg_version:
                            stdin, stdout, stderr = ssh.exec_command("dpkg -l | grep '^ii.*postgresql-server' | head -1")
                            pg_version = stdout.read().decode().strip()
                    
                    # Yöntem 6: PostgreSQL data directory'den versiyon bilgisi
                    if not pg_version or 'PostgreSQL' not in pg_version:
                        stdin, stdout, stderr = ssh.exec_command("find /var/lib/postgresql -name PG_VERSION 2>/dev/null | head -1 | xargs cat")
                        pg_version_raw = stdout.read().decode().strip()
                        if pg_version_raw:
                            pg_version = f"PostgreSQL {pg_version_raw}"
                    
                    # Yöntem 7: Son çare - psql client versiyonu (server ile aynı olabilir)
                    if not pg_version or 'PostgreSQL' not in pg_version:
                        stdin, stdout, stderr = ssh.exec_command("psql --version 2>/dev/null | grep PostgreSQL")
                        pg_version = stdout.read().decode().strip()
                    
                    # Versiyon bilgisini temizle ve sadece PostgreSQL server versiyonunu göster
                    if pg_version and 'PostgreSQL' in pg_version:
                        # Sadece PostgreSQL versiyon numarasını al
                        import re
                        version_match = re.search(r'PostgreSQL (\d+\.\d+)', pg_version)
                        if version_match:
                            server_info['postgresql_version'] = f"PostgreSQL {version_match.group(1)}"
                        else:
                            server_info['postgresql_version'] = pg_version
                    else:
                        server_info['postgresql_version'] = 'PostgreSQL aktif (server versiyonu alınamadı)'
                        
                except Exception as e:
                    server_info['postgresql_version'] = 'PostgreSQL aktif (server versiyonu alınamadı)'
                
                # Replication durumu
                try:
                    stdin, stdout, stderr = ssh.exec_command("sudo -n -u postgres psql -t -c 'SELECT client_addr FROM pg_stat_replication LIMIT 1;' 2>/dev/null")
                    replication_info = stdout.read().decode().strip()
                    if replication_info:
                        server_info['postgresql_replication'] = 'Var'
                    else:
                        server_info['postgresql_replication'] = 'Yok'
                except:
                    pass
                    
        except:
            pass
        
        # pgBackRest durumu
        try:
            stdin, stdout, stderr = ssh.exec_command("which pgbackrest || find /usr -name pgbackrest 2>/dev/null | head -1")
            pgbackrest_info = stdout.read().decode().strip()
            if pgbackrest_info:
                server_info['pgbackrest_status'] = 'Var'
        except:
            pass
        
        ssh.close()
        
    except Exception as e:
        raise Exception(f"SSH bağlantı hatası: {str(e)}")
    
    return server_info

# -------------------- Uzak PostgreSQL bağlantısı --------------------
def _connect_pg(server: Dict[str, Any]):
    _ensure_pg_driver()
    if USING_PG2:
        return _pg.connect(
            host=server["host"],
            port=server["port"],
            dbname=server["dbname"],
            user=server["username"],
            password=server["password"],
            connect_timeout=5,
        )
    # psycopg3
    return _pg.connect(
        host=server["host"],
        port=server["port"],
        dbname=server["dbname"],
        user=server["username"],
        password=server["password"],
        connect_timeout=5,
    )

def run_sql_on_server(server: Dict[str, Any], sql: str) -> Dict[str, Any]:
    info = {"server_id": server["id"], "name": server["name"], "host": server["host"], "port": server["port"], "dbname": server["dbname"]}
    try:
        conn = _connect_pg(server)
        if USING_PG2:
            conn.autocommit = True
            with conn, conn.cursor(cursor_factory=_pg_extras.RealDictCursor) as cur:
                cur.execute(f"SET statement_timeout = {STMT_TIMEOUT_MS};")
                cur.execute(sql)
                if cur.description:
                    cols = [d.name for d in cur.description]
                    rows = cur.fetchmany(MAX_ROWS)
                    truncated = cur.fetchone() is not None
                else:
                    cols = ["status"]; rows = [{"status": f"OK: {cur.statusmessage}"}]; truncated = False
        else:  # psycopg3
            conn.autocommit = True
            with conn.cursor(row_factory=_dict_row) as cur:
                cur.execute(f"SET statement_timeout = {STMT_TIMEOUT_MS};")
                cur.execute(sql)
                if cur.description:
                    cols = [d[0] for d in cur.description]
                    rows = cur.fetchmany(MAX_ROWS)
                    truncated = cur.fetchone() is not None
                else:
                    cols = ["status"]; rows = [{"status": f"OK: {cur.statusmessage}"}]; truncated = False
        conn.close()
        return {"ok": True, "info": info, "columns": cols, "rows": rows, "truncated": truncated}
    except Exception as e:
        return {"ok": False, "info": info, "error": str(e)}

# -------------------- TEMA SCRIPTİ --------------------
THEME_SCRIPT = r"""
<script>
// Dark Mode Toggle
function initTheme() {
  const savedTheme = localStorage.getItem('theme') || 'dark';
  const prefersDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
  const theme = savedTheme === 'dark' || (savedTheme === 'auto' && prefersDark) ? 'dark' : 'light';
  
  document.documentElement.setAttribute('data-theme', theme);
  
  const themeIcon = document.getElementById('themeIcon');
  if (themeIcon) {
    themeIcon.textContent = theme === 'dark' ? '🌙' : '☀️';
  }
  
  localStorage.setItem('theme', theme);
}

function toggleTheme() {
  const currentTheme = document.documentElement.getAttribute('data-theme');
  const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
  
  document.documentElement.setAttribute('data-theme', newTheme);
  
  const themeIcon = document.getElementById('themeIcon');
  if (themeIcon) {
    themeIcon.textContent = newTheme === 'dark' ? '🌙' : '☀️';
  }
  
  localStorage.setItem('theme', newTheme);
}

// Initialize theme on page load
document.addEventListener('DOMContentLoaded', function() {
  initTheme();

  // Add click event to theme toggle
  const themeToggle = document.getElementById('themeToggle');
  if (themeToggle) {
    themeToggle.addEventListener('click', toggleTheme);
  }
});
</script>
"""

# -------------------- TEMPLATES --------------------
# Giriş sayfası template'i
TEMPLATE_LOGIN = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Giriş Yap - PostgreSQL Management System</title>
  <style>
    :root {
      --bg: #0f1216; --panel: #171b21; --muted: #9aa5b1; --txt: #eef2f6; --brand: #50b0ff; --accent: #7cf; --ring: rgba(80,176,255,.35);
      --drop: #0f1216; --hover: #212833;
    }
    
    /* Light mode variables */
    [data-theme="light"] {
      --bg: #f8fafc; --panel: #ffffff; --muted: #64748b; --txt: #1e293b; --brand: #3b82f6; --accent: #06b6d4; --ring: rgba(59,130,246,.35);
      --drop: #ffffff; --hover: #f1f5f9;
    }
    
    /* Dark mode variables */
    [data-theme="dark"] {
      --bg: #0f1216; --panel: #171b21; --muted: #9aa5b1; --txt: #eef2f6; --brand: #50b0ff; --accent: #7cf; --ring: rgba(80,176,255,.35);
      --drop: #0f1216; --hover: #212833;
    }
    
    * { margin: 0; padding: 0; box-sizing: border-box; }
    html, body { height: 100%; }
    body {
      font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif;
      background: var(--bg);
      color: var(--txt);
      display: flex;
      align-items: center;
      justify-content: center;
    }
    
    [data-theme="dark"] body { background: linear-gradient(135deg, #0c0f13, #0f1216); }
    [data-theme="light"] body { background: linear-gradient(135deg, #f1f5f9, #f8fafc); }
    
    .login-container {
      background: var(--panel);
      border-radius: 1rem;
      padding: 2rem;
      box-shadow: 0 20px 40px rgba(0,0,0,0.3);
      border: 1px solid;
      min-width: 400px;
      max-width: 500px;
    }
    
    [data-theme="dark"] .login-container { border-color: #242b37; }
    [data-theme="light"] .login-container { border-color: #e2e8f0; }
    
    .logo {
      text-align: center;
      margin-bottom: 2rem;
    }
    
    .logo h1 {
      font-size: 1.8rem;
      font-weight: 700;
      margin-bottom: 0.5rem;
      background: linear-gradient(135deg, var(--brand), var(--accent));
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
    }
    
    .logo p {
      color: var(--muted);
      font-size: 0.9rem;
    }
    
    .form-group {
      margin-bottom: 1.5rem;
    }
    
    .form-group label {
      display: block;
      margin-bottom: 0.5rem;
      font-weight: 600;
      color: var(--txt);
    }
    
    .form-group input {
      width: 100%;
      padding: 0.75rem 1rem;
      border: 1px solid;
      border-radius: 0.5rem;
      background: var(--panel);
      color: var(--txt);
      font-size: 1rem;
    }
    
    [data-theme="dark"] .form-group input { border-color: #243044; }
    [data-theme="light"] .form-group input { border-color: #e2e8f0; }
    
    .form-group input:focus {
      outline: none;
      border-color: var(--brand);
      box-shadow: 0 0 0 3px var(--ring);
    }
    
    .btn-login {
      width: 100%;
      padding: 0.75rem 1rem;
      background: var(--brand);
      color: white;
      border: none;
      border-radius: 0.5rem;
      font-size: 1rem;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.2s;
    }
    
    .btn-login:hover {
      background: var(--accent);
      transform: translateY(-1px);
    }
    
    .btn-login:active {
      transform: translateY(0);
    }
    
    .theme-toggle {
      position: absolute;
      top: 1rem;
      right: 1rem;
      background: var(--hover);
      border: 1px solid;
      border-radius: 0.5rem;
      padding: 0.5rem;
      cursor: pointer;
      font-size: 1.2rem;
    }
    
    [data-theme="dark"] .theme-toggle { border-color: #243044; }
    [data-theme="light"] .theme-toggle { border-color: #e2e8f0; }
    
    .theme-toggle:hover {
      border-color: var(--brand);
    }
    
    .alert {
      padding: 0.75rem 1rem;
      border-radius: 0.5rem;
      margin-bottom: 1rem;
      border: 1px solid;
    }
    
    .alert-danger {
      background: rgba(239, 68, 68, 0.1);
      border-color: #ef4444;
      color: #ef4444;
    }
    
    .alert-success {
      background: rgba(16, 185, 129, 0.1);
      border-color: #10b981;
      color: #10b981;
    }
  </style>
</head>
<body>
  <button class="theme-toggle" id="themeToggle" title="Dark/Light Mode Toggle">
    <span id="themeIcon">🌙</span>
  </button>
  
  <div class="login-container">
    <div class="logo">
      <h1>PostgreSQL Management</h1>
      <p>Güvenli giriş yapın</p>
    </div>
    
    {% with messages = get_flashed_messages(with_categories=true) %}
      {% if messages %}
        {% for category, message in messages %}
          <div class="alert alert-{{ category }}">
            {{ message }}
          </div>
        {% endfor %}
      {% endif %}
    {% endwith %}
    
    <form method="POST" action="{{ url_for('login') }}">
      <div class="form-group">
        <label for="username">Kullanıcı Adı</label>
        <input type="text" id="username" name="username" required autofocus>
      </div>
      
      <div class="form-group">
        <label for="password">Şifre</label>
        <input type="password" id="password" name="password" required>
      </div>
      
      <button type="submit" class="btn-login">Giriş Yap</button>
    </form>
  </div>

  <script>
    // Dark Mode Toggle
    function initTheme() {
      const savedTheme = localStorage.getItem('theme') || 'dark';
      const prefersDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
      const theme = savedTheme === 'dark' || (savedTheme === 'auto' && prefersDark) ? 'dark' : 'light';
      
      document.documentElement.setAttribute('data-theme', theme);
      
      const themeIcon = document.getElementById('themeIcon');
      if (themeIcon) {
        themeIcon.textContent = theme === 'dark' ? '🌙' : '☀️';
      }
      
      localStorage.setItem('theme', theme);
    }

    function toggleTheme() {
      const currentTheme = document.documentElement.getAttribute('data-theme');
      const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
      
      document.documentElement.setAttribute('data-theme', newTheme);
      
      const themeIcon = document.getElementById('themeIcon');
      if (themeIcon) {
        themeIcon.textContent = newTheme === 'dark' ? '🌙' : '☀️';
      }
      
      localStorage.setItem('theme', newTheme);
    }

    // Initialize theme on page load
    initTheme();

    // Add click event to theme toggle
    const themeToggle = document.getElementById('themeToggle');
    if (themeToggle) {
      themeToggle.addEventListener('click', toggleTheme);
    }
  </script>
  
  {{ theme_script|safe }}
</body>
</html>
"""

# Admin paneli template'i
TEMPLATE_ADMIN = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Admin Panel - PostgreSQL Management System</title>
  <style>
    :root {
      --bg: #0f1216; --panel: #171b21; --muted: #9aa5b1; --txt: #eef2f6; --brand: #50b0ff; --accent: #7cf; --ring: rgba(80,176,255,.35);
      --drop: #0f1216; --hover: #212833;
    }
    
    [data-theme="light"] {
      --bg: #f8fafc; --panel: #ffffff; --muted: #64748b; --txt: #1e293b; --brand: #3b82f6; --accent: #06b6d4; --ring: rgba(59,130,246,.35);
      --drop: #ffffff; --hover: #f1f5f9;
    }
    
    body { 
      font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif;
      background: var(--bg); 
      color: var(--txt);
      margin: 0;
      padding: 1rem;
    }
    
    [data-theme="dark"] body { background: linear-gradient(180deg, #0c0f13, #0f1216); }
    [data-theme="light"] body { background: linear-gradient(180deg, #f1f5f9, #f8fafc); }
    
    .container { max-width: 1200px; margin: 0 auto; }
    .header { display: flex; justify-content: between; align-items: center; margin-bottom: 2rem; }
    .header h1 { margin: 0; }
    .header a { padding: 8px 16px; background: #6b7280; color: white; text-decoration: none; border-radius: 6px; }
    
    .tabs { display: flex; gap: 1rem; margin-bottom: 2rem; }
    .tab { padding: 0.75rem 1.5rem; background: var(--hover); border: 1px solid; border-radius: 0.5rem; cursor: pointer; }
    [data-theme="dark"] .tab { border-color: #243044; }
    [data-theme="light"] .tab { border-color: #e2e8f0; }
    .tab.active { background: var(--brand); color: white; }
    
    .tab-content { display: none; }
    .tab-content.active { display: block; }
    
    .card { background: var(--panel); border: 1px solid; border-radius: 1rem; padding: 1.5rem; margin-bottom: 1rem; }
    [data-theme="dark"] .card { border-color: #242b37; }
    [data-theme="light"] .card { border-color: #e2e8f0; }
    
    .table { width: 100%; border-collapse: collapse; }
    .table th, .table td { padding: 0.75rem; text-align: left; border-bottom: 1px solid; }
    [data-theme="dark"] .table th, [data-theme="dark"] .table td { border-color: #243044; }
    [data-theme="light"] .table th, [data-theme="light"] .table td { border-color: #e2e8f0; }
    .table th { background: var(--hover); font-weight: 600; }
    
    .btn { padding: 0.5rem 1rem; border: none; border-radius: 0.5rem; cursor: pointer; font-weight: 600; }
    .btn-primary { background: var(--brand); color: white; }
    .btn-danger { background: #ef4444; color: white; }
    .btn-success { background: #10b981; color: white; }
    
    .form-group { margin-bottom: 1rem; }
    .form-group label { display: block; margin-bottom: 0.5rem; font-weight: 600; }
    .form-group input, .form-group select { width: 100%; padding: 0.75rem; border: 1px solid; border-radius: 0.5rem; background: var(--panel); color: var(--txt); }
    [data-theme="dark"] .form-group input, [data-theme="dark"] .form-group select { border-color: #243044; }
    [data-theme="light"] .form-group input, [data-theme="light"] .form-group select { border-color: #e2e8f0; }
    
    .checkbox-group { display: flex; gap: 1rem; flex-wrap: wrap; }
    .checkbox-item { display: flex; align-items: center; gap: 0.5rem; }
    
    .theme-toggle { position: fixed; top: 1rem; right: 1rem; background: var(--hover); border: 1px solid; border-radius: 0.5rem; padding: 0.5rem; cursor: pointer; }
    [data-theme="dark"] .theme-toggle { border-color: #243044; }
    [data-theme="light"] .theme-toggle { border-color: #e2e8f0; }
    
    /* İstatistik Kartları */
    .stat-card {
      background: var(--panel);
      border: 1px solid;
      border-radius: 12px;
      padding: 1.5rem;
      display: flex;
      align-items: center;
      gap: 1rem;
      transition: all 0.3s ease;
      box-shadow: 0 4px 12px rgba(0,0,0,0.1);
    }
    
    [data-theme="dark"] .stat-card {
      border-color: #243044;
      box-shadow: 0 4px 12px rgba(0,0,0,0.3);
    }
    
    [data-theme="light"] .stat-card {
      border-color: #e2e8f0;
      box-shadow: 0 4px 12px rgba(0,0,0,0.05);
    }
    
    .stat-card:hover {
      transform: translateY(-2px);
      box-shadow: 0 8px 24px rgba(0,0,0,0.15);
    }
    
    .stat-icon {
      font-size: 2.5rem;
      opacity: 0.8;
    }
    
    .stat-content {
      flex: 1;
    }
    
    .stat-number {
      font-size: 2rem;
      font-weight: 700;
      color: var(--brand);
      line-height: 1;
      margin-bottom: 0.25rem;
    }
    
    .stat-label {
      color: var(--muted);
      font-size: 0.9rem;
      font-weight: 500;
    }
    
    /* Hızlı Erişim Kartları */
    .quick-access-card {
      background: var(--panel);
      border: 1px solid;
      border-radius: 12px;
      padding: 1.5rem;
      transition: all 0.3s ease;
      box-shadow: 0 4px 12px rgba(0,0,0,0.1);
    }
    
    [data-theme="dark"] .quick-access-card {
      border-color: #243044;
      box-shadow: 0 4px 12px rgba(0,0,0,0.3);
    }
    
    [data-theme="light"] .quick-access-card {
      border-color: #e2e8f0;
      box-shadow: 0 4px 12px rgba(0,0,0,0.05);
    }
    
    .quick-access-card:hover {
      transform: translateY(-4px);
      box-shadow: 0 12px 32px rgba(0,0,0,0.2);
      border-color: var(--brand);
    }
    
    .quick-access-icon {
      font-size: 3rem;
      margin-bottom: 1rem;
      opacity: 0.8;
    }
    
    .quick-access-content h4 {
      margin: 0 0 0.5rem 0;
      color: var(--txt);
      font-size: 1.2rem;
      font-weight: 600;
    }
    
    .quick-access-content p {
      color: var(--muted);
      font-size: 0.9rem;
      line-height: 1.5;
      margin: 0 0 1rem 0;
    }
    
    .quick-access-btn {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      padding: 0.75rem 1.5rem;
      background: var(--brand);
      color: white;
      text-decoration: none;
      border-radius: 8px;
      font-weight: 600;
      font-size: 0.9rem;
      transition: all 0.2s ease;
      box-shadow: 0 4px 12px rgba(0,0,0,0.15);
    }
    
    .quick-access-btn:hover {
      background: var(--accent);
      transform: translateY(-1px);
      box-shadow: 0 6px 16px rgba(0,0,0,0.2);
      color: white;
      text-decoration: none;
    }
    
    /* Tıklanabilir İstatistik Kartları */
    .clickable-stat {
      cursor: pointer;
    }
    
    .clickable-stat:hover {
      transform: translateY(-4px);
      box-shadow: 0 12px 32px rgba(0,0,0,0.2);
      border-color: var(--brand);
    }
    
    /* Modal Stilleri */
    .modal {
      display: none;
      position: fixed;
      z-index: 1000;
      left: 0;
      top: 0;
      width: 100%;
      height: 100%;
      background-color: rgba(0,0,0,0.5);
      backdrop-filter: blur(4px);
    }
    
    .modal-content {
      background: var(--panel);
      margin: 5% auto;
      padding: 2rem;
      border-radius: 12px;
      width: 90%;
      max-width: 800px;
      max-height: 80vh;
      overflow-y: auto;
      box-shadow: 0 20px 40px rgba(0,0,0,0.3);
      border: 1px solid var(--border);
    }
    
    .modal-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 1.5rem;
      padding-bottom: 1rem;
      border-bottom: 1px solid var(--border);
    }
    
    .modal-title {
      font-size: 1.5rem;
      font-weight: 700;
      color: var(--txt);
      margin: 0;
    }
    
    .close {
      color: var(--muted);
      font-size: 2rem;
      font-weight: bold;
      cursor: pointer;
      transition: color 0.2s;
    }
    
    .close:hover {
      color: var(--txt);
    }
    
    .modal-table {
      width: 100%;
      border-collapse: collapse;
      margin-top: 1rem;
    }
    
    .modal-table th,
    .modal-table td {
      padding: 0.75rem;
      text-align: left;
      border-bottom: 1px solid var(--border);
    }
    
    .modal-table th {
      background: var(--hover);
      font-weight: 600;
      color: var(--txt);
    }
    
    .modal-table td {
      color: var(--muted);
    }
    
    .modal-table tr:hover {
      background: var(--hover);
    }
    
    .badge {
      padding: 0.25rem 0.5rem;
      border-radius: 0.25rem;
      font-size: 0.75rem;
      font-weight: 600;
    }
    
    .badge-success {
      background: rgba(16, 185, 129, 0.1);
      color: #10b981;
      border: 1px solid rgba(16, 185, 129, 0.2);
    }
    
    .badge-danger {
      background: rgba(239, 68, 68, 0.1);
      color: #ef4444;
      border: 1px solid rgba(239, 68, 68, 0.2);
    }
    
    .badge-info {
      background: rgba(59, 130, 246, 0.1);
      color: #3b82f6;
      border: 1px solid rgba(59, 130, 246, 0.2);
    }
  </style>
</head>
<body>
  <button class="theme-toggle" id="themeToggle" title="Dark/Light Mode Toggle">
    <span id="themeIcon">🌙</span>
  </button>
  
  <div class="container">
    <div class="header">
      <h1>Admin Panel</h1>
      <a href="/">← Ana Sayfa</a>
    </div>
    
    <div class="tabs">
      <div class="tab {% if active_tab == 'dashboard' %}active{% endif %}" onclick="showTab('dashboard')">Dashboard</div>
      <div class="tab {% if active_tab == 'users' %}active{% endif %}" onclick="showTab('users')">Kullanıcı Yönetimi</div>
      {% if session.get('is_admin') or check_permission(session.get('user_id'), 'view_logs') %}
      <div class="tab {% if active_tab == 'logs' %}active{% endif %}" onclick="showTab('logs')">Aktivite Logları</div>
      {% endif %}
    </div>
    
    <!-- Dashboard -->
    <div id="dashboard-tab" class="tab-content {% if active_tab == 'dashboard' %}active{% endif %}">
      <!-- İstatistik Kartları - İlk Satır -->
      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 1.5rem; margin-bottom: 2rem;">
        <!-- Sunucu Sayısı -->
        <div class="stat-card clickable-stat" onclick="showServersModal()" style="background: linear-gradient(135deg, #3b82f6, #2563eb);">
          <div class="stat-icon" style="font-size: 2.5rem;">🖥️</div>
          <div class="stat-content">
            <div class="stat-number" id="adminServers" style="color: white; font-size: 2.5rem;">0</div>
            <div class="stat-label" style="color: rgba(255,255,255,0.9);">Kayıtlı Sunucu</div>
            <div style="color: rgba(255,255,255,0.7); font-size: 0.85rem; margin-top: 0.5rem;">
              <span id="pgServersCount">0</span> PostgreSQL aktif
            </div>
          </div>
        </div>
        
        <!-- Toplam Kullanıcı -->
        <div class="stat-card clickable-stat" onclick="showUsersModal()" style="background: linear-gradient(135deg, #10b981, #059669);">
          <div class="stat-icon" style="font-size: 2.5rem;">👥</div>
          <div class="stat-content">
            <div class="stat-number" id="adminUsers" style="color: white; font-size: 2.5rem;">0</div>
            <div class="stat-label" style="color: rgba(255,255,255,0.9);">Toplam Kullanıcı</div>
            <div style="color: rgba(255,255,255,0.7); font-size: 0.85rem; margin-top: 0.5rem;">
              <span id="activeUsersCount">0</span> aktif
            </div>
          </div>
        </div>
        
        <!-- Bugünkü Sorgular -->
        <div class="stat-card clickable-stat" onclick="showQueriesModal()" style="background: linear-gradient(135deg, #8b5cf6, #7c3aed);">
          <div class="stat-icon" style="font-size: 2.5rem;">📊</div>
          <div class="stat-content">
            <div class="stat-number" id="adminTodayQueries" style="color: white; font-size: 2.5rem;">0</div>
            <div class="stat-label" style="color: rgba(255,255,255,0.9);">Bugünkü Sorgular</div>
            <div style="color: rgba(255,255,255,0.7); font-size: 0.85rem; margin-top: 0.5rem;">
              <span id="weeklyQueries">0</span> bu hafta
            </div>
          </div>
        </div>
        
        <!-- Healthcheck Sayısı -->
        <div class="stat-card" style="background: linear-gradient(135deg, #f59e0b, #d97706);">
          <div class="stat-icon" style="font-size: 2.5rem;">🏥</div>
          <div class="stat-content">
            <div class="stat-number" id="totalHealthchecks" style="color: white; font-size: 2.5rem;">0</div>
            <div class="stat-label" style="color: rgba(255,255,255,0.9);">Toplam Healthcheck</div>
            <div style="color: rgba(255,255,255,0.7); font-size: 0.85rem; margin-top: 0.5rem;">
              <span id="todayHealthchecks">0</span> bugün
            </div>
          </div>
        </div>
      </div>
      
      <!-- İkinci Satır: Detaylı Bilgiler -->
      <div style="display: grid; grid-template-columns: 2fr 1fr; gap: 1.5rem; margin-bottom: 2rem;">
        <!-- Son Aktiviteler -->
        <div class="card" style="max-height: 500px;">
          <h3 style="margin-bottom: 1rem; display: flex; align-items: center; gap: 0.5rem;">
            <span style="font-size: 1.5rem;">📋</span> Son Aktiviteler
          </h3>
          <div id="recentActivities" style="max-height: 400px; overflow-y: auto;">
            <p style="color: var(--muted); text-align: center; padding: 2rem;">Yükleniyor...</p>
          </div>
        </div>
        
        <!-- Sistem Sağlık Durumu -->
        <div class="card">
          <h3 style="margin-bottom: 1rem; display: flex; align-items: center; gap: 0.5rem;">
            <span style="font-size: 1.5rem;">💊</span> Sistem Sağlığı
          </h3>
          <div id="systemHealth" style="display: flex; flex-direction: column; gap: 1rem;">
            <!-- Database Durumu -->
            <div style="background: var(--hover); padding: 1rem; border-radius: 0.75rem; border-left: 4px solid #10b981;">
              <div style="display: flex; justify-content: space-between; align-items: center;">
                <div>
                  <div style="font-weight: 600; color: var(--txt);">💾 Database</div>
                  <div style="font-size: 0.85rem; color: var(--muted); margin-top: 0.25rem;">SQLite</div>
                </div>
                <div style="background: rgba(16, 185, 129, 0.2); color: #10b981; padding: 0.5rem 1rem; border-radius: 0.5rem; font-weight: 600; font-size: 0.9rem;">
                  ✓ Çalışıyor
                </div>
              </div>
            </div>
            
            <!-- API Durumu -->
            <div style="background: var(--hover); padding: 1rem; border-radius: 0.75rem; border-left: 4px solid #3b82f6;">
              <div style="display: flex; justify-content: space-between; align-items: center;">
                <div>
                  <div style="font-weight: 600; color: var(--txt);">🌐 API</div>
                  <div style="font-size: 0.85rem; color: var(--muted); margin-top: 0.25rem;">Flask Backend</div>
                </div>
                <div style="background: rgba(59, 130, 246, 0.2); color: #3b82f6; padding: 0.5rem 1rem; border-radius: 0.5rem; font-weight: 600; font-size: 0.9rem;">
                  ✓ Aktif
                </div>
              </div>
            </div>
            
            <!-- Başarısız Healthcheck -->
            <div style="background: var(--hover); padding: 1rem; border-radius: 0.75rem; border-left: 4px solid #f59e0b;">
              <div style="display: flex; justify-content: space-between; align-items: center;">
                <div>
                  <div style="font-weight: 600; color: var(--txt);">⚠️ Hatalı HC</div>
                  <div style="font-size: 0.85rem; color: var(--muted); margin-top: 0.25rem;">Son 24 saat</div>
                </div>
                <div id="failedHealthchecks" style="background: rgba(245, 158, 11, 0.2); color: #f59e0b; padding: 0.5rem 1rem; border-radius: 0.5rem; font-weight: 600; font-size: 0.9rem;">
                  0
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
      
      <!-- İkinci Satır B: Kritik Uyarılar -->
      <div style="margin-bottom: 2rem;">
        <div class="card" id="criticalAlertsCard" style="border-left: 4px solid #ef4444; display: none;">
          <h3 style="margin-bottom: 1rem; display: flex; align-items: center; gap: 0.5rem; color: #ef4444;">
            <span style="font-size: 1.5rem;">⚠️</span> Kritik Uyarılar
          </h3>
          <div id="criticalAlerts"></div>
        </div>
      </div>
      
      <!-- Üçüncü Satır: Haftalık İstatistikler ve Aktivite Grafiği -->
      <div style="display: grid; grid-template-columns: 1fr 2fr; gap: 1.5rem; margin-bottom: 2rem;">
        <!-- Haftalık Özet -->
        <div class="card">
          <h3 style="margin-bottom: 1rem; display: flex; align-items: center; gap: 0.5rem;">
            <span style="font-size: 1.5rem;">📈</span> Haftalık Özet
          </h3>
          <div id="weeklyStats" style="display: flex; flex-direction: column; gap: 1rem;">
            <p style="color: var(--muted); text-align: center; padding: 2rem;">Yükleniyor...</p>
          </div>
        </div>
        
        <!-- Aktivite Grafiği -->
        <div class="card">
          <h3 style="margin-bottom: 1rem; display: flex; align-items: center; justify-content: space-between;">
            <span style="display: flex; align-items: center; gap: 0.5rem;">
              <span style="font-size: 1.5rem;">📊</span> Son 7 Günün Aktivitesi
            </span>
            <span id="liveTime" style="font-size: 0.9rem; color: var(--muted); font-weight: 500;">--:--:--</span>
          </h3>
          <canvas id="activityChart" width="400" height="200"></canvas>
        </div>
      </div>
      
      <!-- Dördüncü Satır: PostgreSQL Sunucu Durumları ve En Aktif Kullanıcılar -->
      <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; margin-bottom: 2rem;">
        <!-- PostgreSQL Sunucular -->
        <div class="card">
          <h3 style="margin-bottom: 1rem; display: flex; align-items: center; gap: 0.5rem;">
            <span style="font-size: 1.5rem;">🐘</span> PostgreSQL Sunucular
          </h3>
          <div id="postgresqlServers">
            <p style="color: var(--muted); text-align: center; padding: 2rem;">Yükleniyor...</p>
          </div>
        </div>
        
        <!-- En Aktif Kullanıcılar -->
        <div class="card">
          <h3 style="margin-bottom: 1rem; display: flex; align-items: center; gap: 0.5rem;">
            <span style="font-size: 1.5rem;">🏆</span> En Aktif Kullanıcılar (7 gün)
          </h3>
          <div id="topUsers">
            <p style="color: var(--muted); text-align: center; padding: 2rem;">Yükleniyor...</p>
          </div>
        </div>
      </div>
      
      <!-- Beşinci Satır: Database Metrikleri ve Son Girişler -->
      <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; margin-bottom: 2rem;">
        <!-- Database Metrikleri -->
        <div class="card">
          <h3 style="margin-bottom: 1rem; display: flex; align-items: center; gap: 0.5rem;">
            <span style="font-size: 1.5rem;">💾</span> Database Metrikleri
          </h3>
          <div id="databaseMetrics">
            <p style="color: var(--muted); text-align: center; padding: 2rem;">Yükleniyor...</p>
          </div>
        </div>
        
        <!-- Son Girişler -->
        <div class="card">
          <h3 style="margin-bottom: 1rem; display: flex; align-items: center; gap: 0.5rem;">
            <span style="font-size: 1.5rem;">🔑</span> Son Girişler
          </h3>
          <div id="recentLogins">
            <p style="color: var(--muted); text-align: center; padding: 2rem;">Yükleniyor...</p>
          </div>
        </div>
      </div>
      
      <!-- Hızlı Erişim Kartları -->
      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 1.5rem;">
        <div class="quick-access-card" style="background: linear-gradient(135deg, rgba(59, 130, 246, 0.1), rgba(59, 130, 246, 0.05));">
          <div class="quick-access-icon" style="background: linear-gradient(135deg, #3b82f6, #2563eb); color: white; width: 60px; height: 60px; display: flex; align-items: center; justify-content: center; border-radius: 1rem; font-size: 1.8rem;">🔍</div>
          <div class="quick-access-content">
            <h4 style="color: var(--txt); font-size: 1.3rem; margin-bottom: 0.5rem;">Multiquery</h4>
            <p style="color: var(--muted); font-size: 0.95rem; margin-bottom: 1rem;">Birden fazla PostgreSQL sunucusunda eşzamanlı sorgu çalıştırın</p>
            <a href="/multiquery" class="quick-access-btn" style="background: linear-gradient(135deg, #3b82f6, #2563eb); color: white; padding: 0.75rem 1.5rem; border-radius: 0.75rem; text-decoration: none; display: inline-block; font-weight: 600; box-shadow: 0 4px 12px rgba(59, 130, 246, 0.3);">Aç →</a>
          </div>
        </div>
        
        <div class="quick-access-card" style="background: linear-gradient(135deg, rgba(139, 92, 246, 0.1), rgba(139, 92, 246, 0.05));">
          <div class="quick-access-icon" style="background: linear-gradient(135deg, #8b5cf6, #7c3aed); color: white; width: 60px; height: 60px; display: flex; align-items: center; justify-content: center; border-radius: 1rem; font-size: 1.8rem;">⚙️</div>
          <div class="quick-access-content">
            <h4 style="color: var(--txt); font-size: 1.3rem; margin-bottom: 0.5rem;">PostgreSQL Installation</h4>
            <p style="color: var(--muted); font-size: 0.95rem; margin-bottom: 1rem;">Otomatik PostgreSQL kurulum ve yapılandırma</p>
            <a href="/pg_install" class="quick-access-btn" style="background: linear-gradient(135deg, #8b5cf6, #7c3aed); color: white; padding: 0.75rem 1.5rem; border-radius: 0.75rem; text-decoration: none; display: inline-block; font-weight: 600; box-shadow: 0 4px 12px rgba(139, 92, 246, 0.3);">Aç →</a>
          </div>
        </div>
        
        <div class="quick-access-card" style="background: linear-gradient(135deg, rgba(16, 185, 129, 0.1), rgba(16, 185, 129, 0.05));">
          <div class="quick-access-icon" style="background: linear-gradient(135deg, #10b981, #059669); color: white; width: 60px; height: 60px; display: flex; align-items: center; justify-content: center; border-radius: 1rem; font-size: 1.8rem;">🏥</div>
          <div class="quick-access-content">
            <h4 style="color: var(--txt); font-size: 1.3rem; margin-bottom: 0.5rem;">Healthcheck</h4>
            <p style="color: var(--muted); font-size: 0.95rem; margin-bottom: 1rem;">Sunucu sağlık kontrolü ve performans analizi</p>
            <a href="/healthcheck" class="quick-access-btn" style="background: linear-gradient(135deg, #10b981, #059669); color: white; padding: 0.75rem 1.5rem; border-radius: 0.75rem; text-decoration: none; display: inline-block; font-weight: 600; box-shadow: 0 4px 12px rgba(16, 185, 129, 0.3);">Aç →</a>
          </div>
        </div>
        
        <div class="quick-access-card" style="background: linear-gradient(135deg, rgba(245, 158, 11, 0.1), rgba(245, 158, 11, 0.05));">
          <div class="quick-access-icon" style="background: linear-gradient(135deg, #f59e0b, #d97706); color: white; width: 60px; height: 60px; display: flex; align-items: center; justify-content: center; border-radius: 1rem; font-size: 1.8rem;">📋</div>
          <div class="quick-access-content">
            <h4 style="color: var(--txt); font-size: 1.3rem; margin-bottom: 0.5rem;">Sunucu Envanteri</h4>
            <p style="color: var(--muted); font-size: 0.95rem; margin-bottom: 1rem;">Sunucu listesi ve sistem bilgileri</p>
            <a href="/envanter" class="quick-access-btn" style="background: linear-gradient(135deg, #f59e0b, #d97706); color: white; padding: 0.75rem 1.5rem; border-radius: 0.75rem; text-decoration: none; display: inline-block; font-weight: 600; box-shadow: 0 4px 12px rgba(245, 158, 11, 0.3);">Aç →</a>
          </div>
        </div>
      </div>
    </div>
    
    <!-- Kullanıcı Yönetimi -->
    <div id="users-tab" class="tab-content {% if active_tab == 'users' %}active{% endif %}">
      <div class="card">
        <h3>Yeni Kullanıcı Ekle</h3>
        <form method="POST" action="{{ url_for('admin_add_user') }}">
          <div class="form-group">
            <label>Kullanıcı Adı</label>
            <input type="text" name="username" required>
          </div>
          <div class="form-group">
            <label>Tam Ad</label>
            <input type="text" name="full_name" required>
          </div>
          <div class="form-group">
            <label>Şifre</label>
            <input type="password" name="password" required>
          </div>
          
          <div id="permissions-section">
            <h4>Sayfa Yetkileri</h4>
            <p>Bu kullanıcının hangi sayfalara erişebileceğini seçin:</p>
            
            <div class="checkbox-group">
              <div class="checkbox-item">
                <input type="checkbox" name="multiquery" id="perm_multiquery" checked>
                <label for="perm_multiquery">Multiquery</label>
              </div>
              <div class="checkbox-item">
                <input type="checkbox" name="pg_install" id="perm_pg_install">
                <label for="perm_pg_install">PostgreSQL Installation</label>
              </div>
              <div class="checkbox-item">
                <input type="checkbox" name="faydali_linkler" id="perm_faydali_linkler">
                <label for="perm_faydali_linkler">Faydalı Linkler</label>
              </div>
              <div class="checkbox-item">
                <input type="checkbox" name="view_logs" id="perm_view_logs">
                <label for="perm_view_logs">Log Görüntüleme</label>
              </div>
              <div class="checkbox-item">
                <input type="checkbox" name="envanter" id="perm_envanter">
                <label for="perm_envanter">Sunucu Envanteri</label>
              </div>
              <div class="checkbox-item">
                <input type="checkbox" name="healthcheck" id="perm_healthcheck">
                <label for="perm_healthcheck">Healthcheck</label>
              </div>
              {% if session.get('is_admin') %}
              <div class="checkbox-item">
                <input type="checkbox" name="admin_panel" id="perm_admin_panel">
                <label for="perm_admin_panel">Admin Panel</label>
              </div>
              {% endif %}
            </div>
          </div>
          
          <button type="submit" class="btn btn-primary">Kullanıcı Ekle</button>
        </form>
      </div>
      
      <div class="card">
        <h3>Kullanıcılar ve Yetkiler</h3>
        <table class="table">
          <thead>
            <tr>
              <th>ID</th>
              <th>Kullanıcı Adı</th>
              <th>Tam Ad</th>
              <th>Admin</th>
              <th>Aktif</th>
              <th>Yetkiler</th>
              <th>İşlemler</th>
            </tr>
          </thead>
          <tbody>
            {% for user in users %}
            <tr>
              <td>{{ user.id }}</td>
              <td>{{ user.username }}</td>
              <td>{{ user.full_name }}</td>
              <td>{{ 'Evet' if user.is_admin else 'Hayır' }}</td>
              <td>{{ 'Evet' if user.is_active else 'Hayır' }}</td>
              <td>
                {% if user.is_admin %}
                  <span style="color: #10b981; font-weight: bold;">Tüm Yetkiler</span>
                {% else %}
                  {% set user_perms = user_permissions.get(user.id, {}) %}
                  <div style="display: flex; flex-wrap: wrap; gap: 0.25rem;">
                    {% for page, perm_info in page_permissions.items() %}
                      <span style="padding: 0.125rem 0.375rem; border-radius: 0.25rem; font-size: 0.75rem; 
                        {% if user_perms.get(page, False) %}
                          background: #d1fae5; color: #065f46; border: 1px solid #10b981;
                        {% else %}
                          background: #fee2e2; color: #991b1b; border: 1px solid #ef4444;
                        {% endif %}">
                        {{ perm_info.name }}
                      </span>
                    {% endfor %}
                  </div>
                {% endif %}
              </td>
        <td>
          <a href="{{ url_for('admin_edit_user', user_id=user.id) }}" class="btn btn-primary">Düzenle</a>
          {% if session.get('is_admin') %}
          {% if user.id != session.get('user_id') %}
          <form method="POST" action="{{ url_for('admin_delete_user', user_id=user.id) }}" style="display: inline;" 
                onsubmit="return confirm('Kullanıcıyı silmek istediğinizden emin misiniz? Bu işlem geri alınamaz!')">
            <button type="submit" class="btn btn-danger">Sil</button>
          </form>
          {% endif %}
          {% endif %}
          {% if not user.is_admin %}
          <a href="{{ url_for('admin_toggle_user', user_id=user.id) }}" class="btn btn-warning">
            {{ 'Deaktif Et' if user.is_active else 'Aktif Et' }}
          </a>
          {% endif %}
        </td>
            </tr>
            {% endfor %}
          </tbody>
        </table>
      </div>
    </div>
    
    <!-- Aktivite Logları -->
    {% if session.get('is_admin') or check_permission(session.get('user_id'), 'view_logs') %}
    <div id="logs-tab" class="tab-content {% if active_tab == 'logs' %}active{% endif %}">
      <div class="card">
        <h3>Aktivite Logları</h3>
        
        <!-- Arama ve Filtreleme -->
        <div style="margin-bottom: 1rem; padding: 1rem; background: #f8f9fa; border-radius: 4px;">
          <form method="GET" action="{{ url_for('admin_panel') }}" style="display: flex; gap: 1rem; align-items: center; flex-wrap: wrap;">
            <input type="hidden" name="tab" value="logs">
            <div style="flex: 1; min-width: 200px;">
              <input type="text" name="search" placeholder="Kullanıcı, aksiyon, sayfa veya IP ile ara..." 
                     value="{{ search }}" style="width: 100%; padding: 0.5rem; border: 1px solid #ddd; border-radius: 4px;">
            </div>
            <div>
              <select name="page_size" style="padding: 0.5rem; border: 1px solid #ddd; border-radius: 4px;">
                <option value="10" {% if page_size == 10 %}selected{% endif %}>10 kayıt</option>
                <option value="50" {% if page_size == 50 %}selected{% endif %}>50 kayıt</option>
                <option value="100" {% if page_size == 100 %}selected{% endif %}>100 kayıt</option>
                <option value="500" {% if page_size == 500 %}selected{% endif %}>500 kayıt</option>
                <option value="1000" {% if page_size == 1000 %}selected{% endif %}>1000 kayıt</option>
              </select>
            </div>
            <div>
              <button type="submit" style="background: #007bff; color: white; padding: 0.5rem 1rem; border: none; border-radius: 4px; cursor: pointer;">Ara</button>
              <a href="{{ url_for('admin_panel', tab='logs') }}" style="background: #6c757d; color: white; padding: 0.5rem 1rem; border: none; border-radius: 4px; text-decoration: none; display: inline-block;">Temizle</a>
            </div>
          </form>
          
          <!-- Excel Export Butonları -->
          <div style="margin-top: 1rem;">
            <a href="{{ url_for('export_logs_excel', search=search) }}" 
               style="background: #28a745; color: white; padding: 0.5rem 1rem; border: none; border-radius: 4px; text-decoration: none; display: inline-block; margin-right: 0.5rem;">
              📊 Tüm Logları Excel'e Aktar
            </a>
            {% if search %}
            <a href="{{ url_for('export_logs_excel', search=search, filtered='true') }}" 
               style="background: #17a2b8; color: white; padding: 0.5rem 1rem; border: none; border-radius: 4px; text-decoration: none; display: inline-block;">
              📊 Filtrelenmiş Logları Excel'e Aktar
            </a>
            {% endif %}
          </div>
        </div>
        
        <!-- Sayfa Bilgisi -->
        <div style="margin-bottom: 1rem; color: #6c757d;">
          <strong>Toplam {{ total_logs }} kayıt</strong> - 
          Sayfa {{ page }} / {{ total_pages }} 
          ({{ ((page-1) * page_size) + 1 }}-{{ min(page * page_size, total_logs) }} arası gösteriliyor)
        </div>
        <table class="table">
          <thead>
            <tr>
              <th>Tarih/Saat</th>
              <th>Kullanıcı</th>
              <th>Aksiyon</th>
              <th>Detay</th>
              <th>Sayfa</th>
              <th>IP Adresi</th>
              <th>Tarayıcı</th>
            </tr>
          </thead>
          <tbody>
            {% for log in logs %}
            <tr>
              <td>{{ log.timestamp }}</td>
              <td><strong>{{ log.username }}</strong></td>
              <td>
                <span class="badge badge-{% if 'Giriş' in log.action %}success{% elif 'Çıkış' in log.action %}info{% elif 'Sil' in log.action %}danger{% elif 'Ekle' in log.action or 'Düzenle' in log.action %}warning{% elif 'Yetkisi olmayan' in log.action %}danger{% else %}secondary{% endif %}">
                  {{ log.action }}
                </span>
              </td>
              <td>
                {% if log.action and log.action != log.action %}
                  <small>{{ log.action }}</small>
                {% else %}
                  -
                {% endif %}
              </td>
              <td>{{ log.page_name or '-' }}</td>
              <td><code>{{ log.ip_address }}</code></td>
              <td><small>{{ log.user_agent[:30] }}{% if log.user_agent|length > 30 %}...{% endif %}</small></td>
            </tr>
            {% endfor %}
          </tbody>
        </table>
        
        <!-- Sayfalama Navigasyonu -->
        {% if total_pages > 1 %}
        <div style="margin-top: 1rem; display: flex; justify-content: center; align-items: center; gap: 0.5rem;">
          {% if page > 1 %}
          <a href="{{ url_for('admin_panel', search=search, page_size=page_size, page=1, tab='logs') }}" 
             style="padding: 0.5rem; background: #6c757d; color: white; text-decoration: none; border-radius: 4px;">« İlk</a>
          <a href="{{ url_for('admin_panel', search=search, page_size=page_size, page=page-1, tab='logs') }}" 
             style="padding: 0.5rem; background: #6c757d; color: white; text-decoration: none; border-radius: 4px;">‹ Önceki</a>
          {% endif %}
          
          {% for p in range(max(1, page-2), min(total_pages+1, page+3)) %}
          <a href="{{ url_for('admin_panel', search=search, page_size=page_size, page=p, tab='logs') }}" 
             style="padding: 0.5rem; background: {% if p == page %}#007bff{% else %}#6c757d{% endif %}; color: white; text-decoration: none; border-radius: 4px;">
            {{ p }}
          </a>
          {% endfor %}
          
          {% if page < total_pages %}
          <a href="{{ url_for('admin_panel', search=search, page_size=page_size, page=page+1, tab='logs') }}" 
             style="padding: 0.5rem; background: #6c757d; color: white; text-decoration: none; border-radius: 4px;">Sonraki ›</a>
          <a href="{{ url_for('admin_panel', search=search, page_size=page_size, page=total_pages, tab='logs') }}" 
             style="padding: 0.5rem; background: #6c757d; color: white; text-decoration: none; border-radius: 4px;">Son »</a>
          {% endif %}
        </div>
        {% endif %}
      </div>
    </div>
    {% endif %}
  </div>

  <!-- Modals -->
  <!-- Sunucular Modal -->
  <div id="serversModal" class="modal">
    <div class="modal-content">
      <div class="modal-header">
        <h2 class="modal-title">🖥️ Kayıtlı Sunucular</h2>
        <span class="close" onclick="closeModal('serversModal')">&times;</span>
      </div>
      <div id="serversContent">
        <p>Yükleniyor...</p>
      </div>
    </div>
  </div>

  <!-- Kullanıcılar Modal -->
  <div id="usersModal" class="modal">
    <div class="modal-content">
      <div class="modal-header">
        <h2 class="modal-title">👥 Aktif Kullanıcılar</h2>
        <span class="close" onclick="closeModal('usersModal')">&times;</span>
      </div>
      <div id="usersContent">
        <p>Yükleniyor...</p>
      </div>
    </div>
  </div>

  <!-- Sorgular Modal -->
  <div id="queriesModal" class="modal">
    <div class="modal-content">
      <div class="modal-header">
        <h2 class="modal-title">📊 Bugünkü Sorgular</h2>
        <span class="close" onclick="closeModal('queriesModal')">&times;</span>
      </div>
      <div id="queriesContent">
        <p>Yükleniyor...</p>
      </div>
    </div>
  </div>

  <script>
    function showTab(tabName) {
      // Tüm tab'ları gizle
      document.querySelectorAll('.tab-content').forEach(tab => tab.classList.remove('active'));
      document.querySelectorAll('.tab').forEach(tab => tab.classList.remove('active'));
      
      // Seçili tab'ı göster
      document.getElementById(tabName + '-tab').classList.add('active');
      event.target.classList.add('active');
    }

    // Dark Mode Toggle
    function initTheme() {
      const savedTheme = localStorage.getItem('theme') || 'dark';
      const prefersDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
      const theme = savedTheme === 'dark' || (savedTheme === 'auto' && prefersDark) ? 'dark' : 'light';
      
      document.documentElement.setAttribute('data-theme', theme);
      
      const themeIcon = document.getElementById('themeIcon');
      if (themeIcon) {
        themeIcon.textContent = theme === 'dark' ? '🌙' : '☀️';
      }
      
      localStorage.setItem('theme', theme);
    }

    function toggleTheme() {
      const currentTheme = document.documentElement.getAttribute('data-theme');
      const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
      
      document.documentElement.setAttribute('data-theme', newTheme);
      
      const themeIcon = document.getElementById('themeIcon');
      if (themeIcon) {
        themeIcon.textContent = newTheme === 'dark' ? '🌙' : '☀️';
      }
      
      localStorage.setItem('theme', newTheme);
    }

    initTheme();
    document.getElementById('themeToggle').addEventListener('click', toggleTheme);
    
    // Admin Dashboard için istatistikleri yükle
    async function loadAdminStats() {
      try {
        const response = await fetch('/api/admin/dashboard-stats');
        const stats = await response.json();
        
        // Üst istatistikler
        document.getElementById('adminServers').textContent = stats.totalServers || 0;
        document.getElementById('pgServersCount').textContent = stats.pgServers || 0;
        document.getElementById('adminUsers').textContent = stats.totalUsers || 0;
        document.getElementById('activeUsersCount').textContent = stats.activeUsers || 0;
        document.getElementById('adminTodayQueries').textContent = stats.todayQueries || 0;
        document.getElementById('weeklyQueries').textContent = stats.weeklyQueries || 0;
        document.getElementById('totalHealthchecks').textContent = stats.totalHealthchecks || 0;
        document.getElementById('todayHealthchecks').textContent = stats.todayHealthchecks || 0;
        document.getElementById('failedHealthchecks').textContent = stats.failedHealthchecks || 0;
        
        // Son aktiviteleri yükle
        loadRecentActivities(stats.recentActivities || []);
        
        // PostgreSQL sunucuları yükle
        loadPostgreSQLServers(stats.postgresqlServers || []);
        
        // En aktif kullanıcıları yükle
        loadTopUsers(stats.topUsers || []);
        
        // Kritik uyarıları yükle
        loadCriticalAlerts(stats.criticalAlerts || []);
        
        // Haftalık özet yükle
        loadWeeklyStats(stats.weeklyComparison || {});
        
        // Aktivite grafiği çiz
        drawActivityChart(stats.dailyActivities || []);
        
        // Database metrikleri yükle
        loadDatabaseMetrics(stats.databaseMetrics || {});
        
        // Son girişleri yükle
        loadRecentLogins(stats.recentLogins || []);
        
      } catch (error) {
        console.log('Admin istatistikleri yüklenemedi:', error);
      }
    }
    
    // Son aktiviteleri göster
    function loadRecentActivities(activities) {
      const container = document.getElementById('recentActivities');
      if (!activities || activities.length === 0) {
        container.innerHTML = '<p style="color: var(--muted); text-align: center; padding: 2rem;">Henüz aktivite yok</p>';
        return;
      }
      
      let html = '<div style="display: flex; flex-direction: column; gap: 0.75rem;">';
      activities.forEach(activity => {
        const actionColor = activity.action.includes('Giriş') ? '#10b981' : 
                           activity.action.includes('Çıkış') ? '#6b7280' :
                           activity.action.includes('Sil') ? '#ef4444' :
                           activity.action.includes('Ekle') ? '#f59e0b' : '#3b82f6';
        
        html += `
          <div style="background: var(--hover); padding: 1rem; border-radius: 0.75rem; border-left: 4px solid ${actionColor};">
            <div style="display: flex; justify-content: space-between; align-items: start;">
              <div style="flex: 1;">
                <div style="font-weight: 600; color: var(--txt); margin-bottom: 0.25rem;">
                  ${activity.username}
                </div>
                <div style="font-size: 0.9rem; color: var(--muted); margin-bottom: 0.25rem;">
                  ${activity.action}
                </div>
                <div style="font-size: 0.85rem; color: var(--muted);">
                  📍 ${activity.page_name || 'N/A'} • 🕒 ${activity.timestamp}
                </div>
              </div>
            </div>
          </div>
        `;
      });
      html += '</div>';
      container.innerHTML = html;
    }
    
    // PostgreSQL sunucuları göster
    function loadPostgreSQLServers(servers) {
      const container = document.getElementById('postgresqlServers');
      if (!servers || servers.length === 0) {
        container.innerHTML = '<p style="color: var(--muted); text-align: center; padding: 2rem;">PostgreSQL sunucusu bulunamadı</p>';
        return;
      }
      
      let html = '<div style="display: flex; flex-direction: column; gap: 0.75rem;">';
      servers.slice(0, 5).forEach(server => {
        const statusColor = server.postgresql_status === 'Var' ? '#10b981' : '#6b7280';
        html += `
          <div style="background: var(--hover); padding: 1rem; border-radius: 0.75rem; border-left: 4px solid ${statusColor};">
            <div style="display: flex; justify-content: space-between; align-items: center;">
              <div>
                <div style="font-weight: 600; color: var(--txt);">${server.hostname}</div>
                <div style="font-size: 0.85rem; color: var(--muted); margin-top: 0.25rem;">
                  ${server.ip} ${server.postgresql_version ? '• ' + server.postgresql_version : ''}
                </div>
              </div>
              <div style="background: rgba(16, 185, 129, 0.2); color: #10b981; padding: 0.35rem 0.75rem; border-radius: 0.5rem; font-size: 0.85rem; font-weight: 600;">
                ✓
              </div>
            </div>
          </div>
        `;
      });
      html += '</div>';
      
      if (servers.length > 5) {
        html += `<div style="text-align: center; margin-top: 1rem; padding: 0.75rem; color: var(--muted); font-size: 0.9rem;">
          ve ${servers.length - 5} sunucu daha...
        </div>`;
      }
      
      container.innerHTML = html;
    }
    
    // En aktif kullanıcıları göster
    function loadTopUsers(users) {
      const container = document.getElementById('topUsers');
      if (!users || users.length === 0) {
        container.innerHTML = '<p style="color: var(--muted); text-align: center; padding: 2rem;">Veri yok</p>';
        return;
      }
      
      let html = '<div style="display: flex; flex-direction: column; gap: 0.75rem;">';
      users.forEach((user, index) => {
        const medalColors = ['#fbbf24', '#94a3b8', '#c2410c'];
        const medals = ['🥇', '🥈', '🥉'];
        const medal = index < 3 ? medals[index] : '👤';
        const borderColor = index < 3 ? medalColors[index] : '#6b7280';
        
        html += `
          <div style="background: var(--hover); padding: 1rem; border-radius: 0.75rem; border-left: 4px solid ${borderColor};">
            <div style="display: flex; justify-content: space-between; align-items: center;">
              <div style="display: flex; align-items: center; gap: 0.75rem;">
                <div style="font-size: 1.5rem;">${medal}</div>
                <div>
                  <div style="font-weight: 600; color: var(--txt);">${user.username}</div>
                  <div style="font-size: 0.85rem; color: var(--muted);">${user.full_name}</div>
                </div>
              </div>
              <div style="background: rgba(59, 130, 246, 0.2); color: #3b82f6; padding: 0.35rem 0.75rem; border-radius: 0.5rem; font-size: 0.85rem; font-weight: 600;">
                ${user.activity_count} işlem
              </div>
            </div>
          </div>
        `;
      });
      html += '</div>';
      container.innerHTML = html;
    }
    
    // Kritik uyarıları göster
    function loadCriticalAlerts(alerts) {
      const container = document.getElementById('criticalAlerts');
      const card = document.getElementById('criticalAlertsCard');
      
      if (!alerts || alerts.length === 0) {
        card.style.display = 'none';
        return;
      }
      
      card.style.display = 'block';
      let html = '<div style="display: flex; flex-direction: column; gap: 0.75rem;">';
      
      alerts.forEach(alert => {
        const severity = alert.severity || 'warning';
        const colors = {
          critical: { bg: 'rgba(239, 68, 68, 0.1)', border: '#ef4444', text: '#ef4444', icon: '🔴' },
          warning: { bg: 'rgba(245, 158, 11, 0.1)', border: '#f59e0b', text: '#f59e0b', icon: '🟡' },
          info: { bg: 'rgba(59, 130, 246, 0.1)', border: '#3b82f6', text: '#3b82f6', icon: '🔵' }
        };
        const color = colors[severity] || colors.warning;
        
        html += `
          <div style="background: ${color.bg}; padding: 1rem; border-radius: 0.75rem; border-left: 4px solid ${color.border}; border: 1px solid ${color.border};">
            <div style="display: flex; align-items: start; gap: 0.75rem;">
              <div style="font-size: 1.5rem;">${color.icon}</div>
              <div style="flex: 1;">
                <div style="font-weight: 600; color: ${color.text}; margin-bottom: 0.25rem;">${alert.title}</div>
                <div style="font-size: 0.9rem; color: var(--txt);">${alert.message}</div>
                ${alert.action ? `<div style="margin-top: 0.5rem;"><a href="${alert.action}" style="color: ${color.text}; font-size: 0.85rem; text-decoration: underline;">Detay →</a></div>` : ''}
              </div>
            </div>
          </div>
        `;
      });
      
      html += '</div>';
      container.innerHTML = html;
    }
    
    // Haftalık istatistikleri göster
    function loadWeeklyStats(comparison) {
      const container = document.getElementById('weeklyStats');
      
      const stats = [
        { label: 'Toplam Sorgu', value: comparison.weeklyQueries || 0, change: comparison.queryChange || 0, icon: '📊' },
        { label: 'Healthcheck', value: comparison.weeklyHealthchecks || 0, change: comparison.healthcheckChange || 0, icon: '🏥' },
        { label: 'Kullanıcı Girişi', value: comparison.weeklyLogins || 0, change: comparison.loginChange || 0, icon: '🔑' },
        { label: 'Sunucu Eklendi', value: comparison.serversAdded || 0, change: 0, icon: '🖥️' }
      ];
      
      let html = '';
      stats.forEach(stat => {
        const isPositive = stat.change > 0;
        const changeColor = isPositive ? '#10b981' : stat.change < 0 ? '#ef4444' : '#6b7280';
        const changeIcon = isPositive ? '📈' : stat.change < 0 ? '📉' : '➖';
        
        html += `
          <div style="background: var(--hover); padding: 1rem; border-radius: 0.75rem; border-left: 4px solid #3b82f6;">
            <div style="display: flex; justify-content: space-between; align-items: start;">
              <div style="display: flex; align-items: center; gap: 0.75rem;">
                <div style="font-size: 1.8rem;">${stat.icon}</div>
                <div>
                  <div style="font-size: 1.5rem; font-weight: 700; color: var(--txt);">${stat.value}</div>
                  <div style="font-size: 0.85rem; color: var(--muted);">${stat.label}</div>
                </div>
              </div>
              ${stat.change !== 0 ? `
                <div style="background: ${changeColor}20; color: ${changeColor}; padding: 0.35rem 0.75rem; border-radius: 0.5rem; font-size: 0.85rem; font-weight: 600;">
                  ${changeIcon} ${Math.abs(stat.change)}%
                </div>
              ` : ''}
            </div>
          </div>
        `;
      });
      
      container.innerHTML = html;
    }
    
    // Aktivite grafiği çiz (basit canvas chart)
    function drawActivityChart(dailyData) {
      const canvas = document.getElementById('activityChart');
      if (!canvas) return;
      
      const ctx = canvas.getContext('2d');
      const width = canvas.width;
      const height = canvas.height;
      const padding = 40;
      
      // Canvas temizle
      ctx.clearRect(0, 0, width, height);
      
      if (!dailyData || dailyData.length === 0) {
        ctx.fillStyle = getComputedStyle(document.documentElement).getPropertyValue('--muted');
        ctx.font = '14px system-ui';
        ctx.textAlign = 'center';
        ctx.fillText('Veri bulunamadı', width / 2, height / 2);
        return;
      }
      
      // Değerleri al
      const values = dailyData.map(d => d.count);
      const labels = dailyData.map(d => d.day);
      const maxValue = Math.max(...values, 1);
      
      // Arka plan grid çizgileri
      ctx.strokeStyle = getComputedStyle(document.documentElement).getPropertyValue('--border');
      ctx.lineWidth = 1;
      for (let i = 0; i <= 4; i++) {
        const y = padding + (height - 2 * padding) * i / 4;
        ctx.beginPath();
        ctx.moveTo(padding, y);
        ctx.lineTo(width - padding, y);
        ctx.stroke();
      }
      
      // Grafik çiz
      ctx.beginPath();
      ctx.strokeStyle = '#3b82f6';
      ctx.lineWidth = 3;
      ctx.lineJoin = 'round';
      
      const stepX = (width - 2 * padding) / (values.length - 1);
      
      values.forEach((value, index) => {
        const x = padding + index * stepX;
        const y = height - padding - ((value / maxValue) * (height - 2 * padding));
        
        if (index === 0) {
          ctx.moveTo(x, y);
        } else {
          ctx.lineTo(x, y);
        }
      });
      ctx.stroke();
      
      // Noktalar ve gradient dolgu
      const gradient = ctx.createLinearGradient(0, padding, 0, height - padding);
      gradient.addColorStop(0, 'rgba(59, 130, 246, 0.3)');
      gradient.addColorStop(1, 'rgba(59, 130, 246, 0.05)');
      
      ctx.lineTo(width - padding, height - padding);
      ctx.lineTo(padding, height - padding);
      ctx.closePath();
      ctx.fillStyle = gradient;
      ctx.fill();
      
      // Noktalar ekle
      values.forEach((value, index) => {
        const x = padding + index * stepX;
        const y = height - padding - ((value / maxValue) * (height - 2 * padding));
        
        ctx.beginPath();
        ctx.arc(x, y, 5, 0, 2 * Math.PI);
        ctx.fillStyle = '#3b82f6';
        ctx.fill();
        ctx.strokeStyle = '#ffffff';
        ctx.lineWidth = 2;
        ctx.stroke();
        
        // Değer etiketi
        ctx.fillStyle = getComputedStyle(document.documentElement).getPropertyValue('--txt');
        ctx.font = 'bold 12px system-ui';
        ctx.textAlign = 'center';
        ctx.fillText(value, x, y - 15);
      });
      
      // X ekseni etiketleri
      ctx.fillStyle = getComputedStyle(document.documentElement).getPropertyValue('--muted');
      ctx.font = '11px system-ui';
      ctx.textAlign = 'center';
      labels.forEach((label, index) => {
        const x = padding + index * stepX;
        ctx.fillText(label, x, height - 10);
      });
    }
    
    // Database metriklerini göster
    function loadDatabaseMetrics(metrics) {
      const container = document.getElementById('databaseMetrics');
      
      html = `
        <div style="display: flex; flex-direction: column; gap: 1rem;">
          <div style="background: var(--hover); padding: 1rem; border-radius: 0.75rem; border-left: 4px solid #3b82f6;">
            <div style="display: flex; justify-content: space-between; align-items: center;">
              <div>
                <div style="font-size: 0.85rem; color: var(--muted);">SQLite Dosya Boyutu</div>
                <div style="font-weight: 700; color: var(--txt); font-size: 1.3rem; margin-top: 0.25rem;">${metrics.dbSize || 'N/A'}</div>
              </div>
              <div style="font-size: 2rem;">💾</div>
            </div>
          </div>
          
          <div style="background: var(--hover); padding: 1rem; border-radius: 0.75rem; border-left: 4px solid #10b981;">
            <div style="display: flex; justify-content: space-between; align-items: center;">
              <div>
                <div style="font-size: 0.85rem; color: var(--muted);">Toplam Kayıt</div>
                <div style="font-weight: 700; color: var(--txt); font-size: 1.3rem; margin-top: 0.25rem;">${metrics.totalRecords || 0}</div>
              </div>
              <div style="font-size: 2rem;">📝</div>
            </div>
          </div>
          
          <div style="background: var(--hover); padding: 1rem; border-radius: 0.75rem; border-left: 4px solid #f59e0b;">
            <div style="display: flex; justify-content: space-between; align-items: center;">
              <div>
                <div style="font-size: 0.85rem; color: var(--muted);">Healthcheck Başarı Oranı</div>
                <div style="font-weight: 700; color: var(--txt); font-size: 1.3rem; margin-top: 0.25rem;">${metrics.healthcheckSuccessRate || '0'}%</div>
              </div>
              <div style="font-size: 2rem;">✅</div>
            </div>
            <div style="margin-top: 0.75rem; background: var(--panel); height: 8px; border-radius: 4px; overflow: hidden;">
              <div style="background: linear-gradient(90deg, #10b981, #059669); height: 100%; width: ${metrics.healthcheckSuccessRate || 0}%; transition: width 0.5s ease;"></div>
            </div>
          </div>
          
          <div style="background: var(--hover); padding: 1rem; border-radius: 0.75rem; border-left: 4px solid #8b5cf6;">
            <div style="display: flex; justify-content: space-between; align-items: center;">
              <div>
                <div style="font-size: 0.85rem; color: var(--muted);">Sistem Uptime</div>
                <div style="font-weight: 700; color: var(--txt); font-size: 1.3rem; margin-top: 0.25rem;">${metrics.systemUptime || 'N/A'}</div>
              </div>
              <div style="font-size: 2rem;">⏱️</div>
            </div>
          </div>
        </div>
      `;
      
      container.innerHTML = html;
    }
    
    // Son girişleri göster
    function loadRecentLogins(logins) {
      const container = document.getElementById('recentLogins');
      if (!logins || logins.length === 0) {
        container.innerHTML = '<p style="color: var(--muted); text-align: center; padding: 2rem;">Henüz giriş yapılmamış</p>';
        return;
      }
      
      let html = '<div style="display: flex; flex-direction: column; gap: 0.75rem;">';
      logins.forEach((login, index) => {
        html += `
          <div style="background: var(--hover); padding: 1rem; border-radius: 0.75rem; border-left: 4px solid #10b981;">
            <div style="display: flex; justify-content: space-between; align-items: center;">
              <div style="display: flex; align-items: center; gap: 0.75rem;">
                <div style="background: linear-gradient(135deg, #10b981, #059669); color: white; width: 40px; height: 40px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-weight: 700; font-size: 1.1rem;">
                  ${login.username.charAt(0).toUpperCase()}
                </div>
                <div>
                  <div style="font-weight: 600; color: var(--txt);">${login.username}</div>
                  <div style="font-size: 0.85rem; color: var(--muted);">${login.full_name}</div>
                </div>
              </div>
              <div style="text-align: right;">
                <div style="font-size: 0.85rem; color: var(--muted);">🕒 ${login.timestamp}</div>
                <div style="font-size: 0.8rem; color: var(--muted); margin-top: 0.25rem;">📍 ${login.ip_address || 'N/A'}</div>
              </div>
            </div>
          </div>
        `;
      });
      html += '</div>';
      container.innerHTML = html;
    }
    
    // Canlı saat
    function updateLiveTime() {
      const timeElement = document.getElementById('liveTime');
      if (!timeElement) return;
      
      const now = new Date();
      const hours = String(now.getHours()).padStart(2, '0');
      const minutes = String(now.getMinutes()).padStart(2, '0');
      const seconds = String(now.getSeconds()).padStart(2, '0');
      timeElement.textContent = `${hours}:${minutes}:${seconds}`;
    }
    
    // Her saniye saati güncelle
    setInterval(updateLiveTime, 1000);
    updateLiveTime();

    // Dashboard sekmesi aktif olduğunda istatistikleri yükle
    function showTab(tabName) {
      // Tüm tab'ları gizle
      document.querySelectorAll('.tab-content').forEach(tab => tab.classList.remove('active'));
      document.querySelectorAll('.tab').forEach(tab => tab.classList.remove('active'));
      
      // Seçili tab'ı göster
      document.getElementById(tabName + '-tab').classList.add('active');
      document.querySelector(`[onclick="showTab('${tabName}')"]`).classList.add('active');
      
      // Dashboard sekmesi aktifse istatistikleri yükle
      if (tabName === 'dashboard') {
        loadAdminStats();
      }
    }
    
    // Sayfa yüklendiğinde dashboard aktifse verileri yükle
    document.addEventListener('DOMContentLoaded', function() {
      const dashboardTab = document.getElementById('dashboard-tab');
      if (dashboardTab && dashboardTab.classList.contains('active')) {
        loadAdminStats();
      }
    });

    // Modal fonksiyonları
    function showModal(modalId) {
      document.getElementById(modalId).style.display = 'block';
    }

    function closeModal(modalId) {
      document.getElementById(modalId).style.display = 'none';
    }

    // Sunucular modal'ını göster
    async function showServersModal() {
      showModal('serversModal');
      
      try {
        const response = await fetch('/api/servers');
        const servers = await response.json();
        
        let html = '<table class="modal-table">';
        html += '<thead><tr><th>ID</th><th>Ad</th><th>Host</th><th>Port</th><th>Database</th><th>Kullanıcı</th></tr></thead>';
        html += '<tbody>';
        
        if (servers.length === 0) {
          html += '<tr><td colspan="6" style="text-align: center; color: var(--muted);">Henüz kayıtlı sunucu yok</td></tr>';
        } else {
          servers.forEach(server => {
            html += `<tr>
              <td>${server.id}</td>
              <td><strong>${server.name}</strong></td>
              <td>${server.host}</td>
              <td>${server.port}</td>
              <td>${server.dbname}</td>
              <td>${server.username}</td>
            </tr>`;
          });
        }
        
        html += '</tbody></table>';
        document.getElementById('serversContent').innerHTML = html;
      } catch (error) {
        document.getElementById('serversContent').innerHTML = '<p style="color: #ef4444;">Sunucular yüklenirken hata oluştu.</p>';
      }
    }

    // Kullanıcılar modal'ını göster
    async function showUsersModal() {
      showModal('usersModal');
      
      try {
        const response = await fetch('/api/admin/users');
        const users = await response.json();
        
        let html = '<table class="modal-table">';
        html += '<thead><tr><th>ID</th><th>Kullanıcı Adı</th><th>Ad Soyad</th><th>Durum</th><th>Admin</th><th>Son Giriş</th></tr></thead>';
        html += '<tbody>';
        
        if (users.length === 0) {
          html += '<tr><td colspan="6" style="text-align: center; color: var(--muted);">Kullanıcı bulunamadı</td></tr>';
        } else {
          users.forEach(user => {
            const statusClass = user.is_active ? 'badge-success' : 'badge-danger';
            const statusText = user.is_active ? 'Aktif' : 'Pasif';
            const adminBadge = user.is_admin ? '<span class="badge badge-info">Admin</span>' : '<span class="badge badge-success">Kullanıcı</span>';
            
            html += `<tr>
              <td>${user.id}</td>
              <td><strong>${user.username}</strong></td>
              <td>${user.full_name || '-'}</td>
              <td><span class="badge ${statusClass}">${statusText}</span></td>
              <td>${adminBadge}</td>
              <td>${user.last_login || '-'}</td>
            </tr>`;
          });
        }
        
        html += '</tbody></table>';
        document.getElementById('usersContent').innerHTML = html;
      } catch (error) {
        document.getElementById('usersContent').innerHTML = '<p style="color: #ef4444;">Kullanıcılar yüklenirken hata oluştu.</p>';
      }
    }

    // Sorgular modal'ını göster
    async function showQueriesModal() {
      showModal('queriesModal');
      
      try {
        const response = await fetch('/api/admin/today-queries');
        const queries = await response.json();
        
        let html = '<table class="modal-table">';
        html += '<thead><tr><th>Tarih/Saat</th><th>Kullanıcı</th><th>Aksiyon</th><th>Detay</th><th>Sayfa</th></tr></thead>';
        html += '<tbody>';
        
        if (queries.length === 0) {
          html += '<tr><td colspan="5" style="text-align: center; color: var(--muted);">Bugün henüz sorgu çalıştırılmamış</td></tr>';
        } else {
          queries.forEach(query => {
            html += `<tr>
              <td>${query.timestamp}</td>
              <td><strong>${query.username}</strong></td>
              <td>${query.action}</td>
              <td style="max-width: 300px; word-break: break-all;">${query.details || '-'}</td>
              <td>${query.page_name || '-'}</td>
            </tr>`;
          });
        }
        
        html += '</tbody></table>';
        document.getElementById('queriesContent').innerHTML = html;
      } catch (error) {
        document.getElementById('queriesContent').innerHTML = '<p style="color: #ef4444;">Sorgular yüklenirken hata oluştu.</p>';
      }
    }

    // Modal dışına tıklandığında kapat
    window.onclick = function(event) {
      if (event.target.classList.contains('modal')) {
        event.target.style.display = 'none';
      }
    }
    
    // Sayfa yüklendiğinde dashboard sekmesi aktifse istatistikleri yükle
    document.addEventListener('DOMContentLoaded', function() {
      const activeTab = '{{ active_tab }}';
      if (activeTab === 'dashboard') {
        loadAdminStats();
      }
    });
    
  </script>
</body>
</html>
"""

# d1.html (landing) — Hash router içinde Multiquery Panel sayfası /multiquery butonuna gider
TEMPLATE_LANDING = r"""<!doctype html>
<html lang="tr">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>PostgreSQL Management System</title>
  <style>
    :root{
      --bg:#0f1216; --panel:#171b21; --muted:#9aa5b1; --txt:#eef2f6; --brand:#50b0ff; --accent:#7cf; --ring:rgba(80,176,255,.35);
      --drop:#0f1216; --hover:#212833;
    }
    
    /* Light mode variables */
    [data-theme="light"] {
      --bg: #f8fafc; --panel: #ffffff; --muted: #64748b; --txt: #1e293b; --brand: #3b82f6; --accent: #06b6d4; --ring: rgba(59,130,246,.35);
      --drop: #ffffff; --hover: #f1f5f9;
    }
    
    /* Dark mode variables */
    [data-theme="dark"] {
      --bg: #0f1216; --panel: #171b21; --muted: #9aa5b1; --txt: #eef2f6; --brand: #50b0ff; --accent: #7cf; --ring: rgba(80,176,255,.35);
      --drop: #0f1216; --hover: #212833;
    }
    html,body{height:100%}
    body{margin:0; font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, "Apple Color Emoji","Segoe UI Emoji"; color:var(--txt)}
    [data-theme="dark"] body{background:linear-gradient(180deg,#0c0f13,#0f1216)}
    [data-theme="light"] body{background:linear-gradient(180deg,#f1f5f9,#f8fafc)}
    .wrap{min-height:100%; display:flex; flex-direction:column}

    /* Header */
    .header{position:sticky; top:0; z-index:50; backdrop-filter:saturate(1.2) blur(8px); border-bottom:1px solid #232a36}
    [data-theme="dark"] .header{background:rgba(15,18,22,.7); border-bottom:1px solid #232a36}
    [data-theme="light"] .header{background:rgba(248,250,252,.7); border-bottom:1px solid #e2e8f0}
    .bar{max-width:1200px; margin:auto; display:flex; align-items:center; gap:.75rem; padding:.75rem 1rem}
    .brand{display:flex; align-items:center; gap:.6rem; font-weight:700; letter-spacing:.3px}
    .logo{width:34px; height:34px; border-radius:10px; background:linear-gradient(135deg,var(--brand),#7a9dff); box-shadow:0 0 0 3px var(--ring) inset}
    .subtitle{color:var(--muted); font-weight:500; font-size:.9rem}

    /* Menu */
    .menu{margin-left:auto; display:flex; gap:.25rem; align-items:stretch}
    .menu-item{position:relative}
    .menu-btn{all:unset; cursor:pointer; display:flex; align-items:center; gap:.5rem; padding:.55rem .75rem; border-radius:.7rem; color:var(--txt); border:1px solid transparent}
    .menu-btn:hover{background:var(--hover); border-color:#2a3444}
    .menu-btn:focus-visible{outline:2px solid var(--brand); outline-offset:2px}
    .caret{width:0;height:0;border-left:5px solid transparent;border-right:5px solid transparent;border-top:6px solid var(--muted); transition:transform .2s}
    .menu-item[aria-expanded="true"] .caret{transform:rotate(180deg)}

    /* Dropdown */
    .dropdown{position:absolute; left:0; top:100%; min-width:220px; display:none; background:var(--drop); border-radius:.8rem; padding:.4rem; box-shadow:0 12px 28px rgba(0,0,0,.45)}
    [data-theme="dark"] .dropdown{border:1px solid #232a36; box-shadow:0 12px 28px rgba(0,0,0,.45)}
    [data-theme="light"] .dropdown{border:1px solid #e2e8f0; box-shadow:0 12px 28px rgba(0,0,0,.1)}
    .menu-item:hover > .dropdown{display:block}
    .dropdown a{display:flex; justify-content:space-between; gap:.75rem; text-decoration:none; color:var(--txt); padding:.55rem .7rem; border-radius:.6rem}
    .dropdown a:hover{background:var(--hover)}
    .pill{color:#a6ffce; font-size:.72rem; padding:.12rem .45rem; border-radius:999px; background:#173b2a; border:1px solid #275f45}

    /* Submenu styles */
    .submenu-item{position:relative}
    .submenu-trigger{display:flex; justify-content:space-between; align-items:center; gap:.75rem; text-decoration:none; color:var(--txt); padding:.55rem .7rem; border-radius:.6rem; cursor:pointer}
    .submenu-trigger:hover{background:var(--hover)}
    .submenu-caret{transition:transform .2s; font-size:.9em}
    .submenu-item:hover .submenu-caret{transform:rotate(90deg)}
    .submenu{position:absolute; left:100%; top:0; min-width:220px; display:none; background:var(--drop); border-radius:.8rem; padding:.4rem; box-shadow:0 12px 28px rgba(0,0,0,.45); z-index:1000}
    [data-theme="dark"] .submenu{border:1px solid #232a36; box-shadow:0 12px 28px rgba(0,0,0,.45)}
    [data-theme="light"] .submenu{border:1px solid #e2e8f0; box-shadow:0 12px 28px rgba(0,0,0,.1)}
    .submenu-item:hover > .submenu{display:block}
    .submenu a{display:block; text-decoration:none; color:var(--txt); padding:.45rem .6rem; border-radius:.5rem; font-size:.9rem}
    .submenu a:hover{background:var(--hover)}

    /* Mobile */
    .hamburger{display:none; margin-left:auto}
    .hamburger button{all:unset; cursor:pointer; padding:.45rem .55rem; border-radius:.6rem}
    .hamburger button:hover{background:var(--hover)}
    @media (max-width: 980px){
      .menu{display:none; position:absolute; left:0; right:0; top:56px; background:var(--drop); padding:.5rem}
      [data-theme="dark"] .menu{border-top:1px solid #232a36}
      [data-theme="light"] .menu{border-top:1px solid #e2e8f0}
      .menu.open{display:flex; flex-direction:column; gap:.35rem}
      .menu-item:hover > .dropdown{display:none}
      .menu-item[aria-expanded="true"] > .dropdown{display:block; position:relative; top:auto; left:auto; box-shadow:none; border:none; background:transparent; padding:.25rem}
    }

    /* Main */
    main{max-width:1200px; margin:1.2rem auto; padding:0 1rem 2rem}
    .panel{background:var(--panel); border-radius:1rem; padding:1rem}
    [data-theme="dark"] .panel{border:1px solid #242b37}
    [data-theme="light"] .panel{border:1px solid #e2e8f0}
    .cta{display:flex; flex-wrap:wrap; gap:.7rem; margin-top:1rem}
    .tag{padding:.25rem .5rem; border-radius:.5rem; font-size:.82rem}
    [data-theme="dark"] .tag{background:#16202b; border:1px solid #233246; color:#b5c7dd}
    [data-theme="light"] .tag{background:#f1f5f9; border:1px solid #cbd5e1; color:#475569}
    .muted{color:var(--muted)}
    .grid{display:grid; grid-template-columns:repeat(12,1fr); gap:1rem}
    .col-8{grid-column:span 8}
    .col-4{grid-column:span 4}
    @media (max-width:980px){.grid{grid-template-columns:1fr}.col-8,.col-4{grid-column:1}}

    .card{background:var(--panel); border-radius:.9rem; padding:1rem}
    [data-theme="dark"] .card{border:1px solid #243044}
    [data-theme="light"] .card{border:1px solid #e2e8f0}
    .card h3{margin:.2rem 0 .5rem}
    .footer{margin-top:auto; padding:1rem; color:var(--muted); text-align:center}
    [data-theme="dark"] .footer{border-top:1px solid #222a38}
    [data-theme="light"] .footer{border-top:1px solid #e2e8f0}
    .kbd{font-family:ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; padding:.1rem .35rem; border-radius:.35rem}
    [data-theme="dark"] .kbd{background:#141a23; border:1px solid #243044}
    [data-theme="light"] .kbd{background:#f1f5f9; border:1px solid #cbd5e1; color:#475569}
    .btn{display:inline-flex; align-items:center; justify-content:center; gap:.5rem; padding:.8rem 1.1rem; border-radius:.7rem; cursor:pointer; text-decoration:none; font-weight:600; box-shadow:0 8px 24px rgba(0,0,0,.35)}
    [data-theme="dark"] .btn{border:1px solid #294058; color:#eaf2ff; background:linear-gradient(180deg,#1a2634,#15202c)}
    [data-theme="dark"] .btn:hover{background:#192432; border-color:#345575}
    [data-theme="light"] .btn{border:1px solid #3b82f6; color:#ffffff; background:linear-gradient(180deg,#3b82f6,#2563eb)}
    [data-theme="light"] .btn:hover{background:linear-gradient(180deg,#2563eb,#1d4ed8)}
    .btn:active{transform:translateY(1px)}
    
    /* Theme Toggle Button */
    #themeToggle:hover{background:var(--hover); border-color:var(--brand);}
    [data-theme="dark"] #themeToggle:hover{border-color:#50b0ff;}
    [data-theme="light"] #themeToggle:hover{border-color:#3b82f6;}
    
    /* Global text color fixes for better visibility */
    p, div, span, td, th, label, h1, h2, h3, h4, h5, h6 { color: var(--txt); }
    .text-muted { color: var(--muted) !important; }
    .alert { color: var(--txt); }
    .btn { color: white; }
    .btn-outline-secondary { color: var(--muted); border-color: var(--muted); }
    .btn-outline-secondary:hover { background: var(--muted); border-color: var(--muted); color: white; }
    
  </style>
</head>
<body>
  <div class="wrap">
    <!-- Header / Navbar -->
    <header class="header" role="banner">
      <div class="bar">
        <div class="logo" aria-hidden="true"></div>
<a class="brand" href="/" aria-label="Ana sayfa">
  PostgreSQL Management System
  <span class="subtitle">• Faruk Erdem’den sevgilerle</span>
</a>

        <div class="titleblock"></div>

        <div style="display: flex; align-items: center; gap: 0.5rem; margin-left: auto;">
          <!-- User Info -->
          <span style="color: var(--muted); font-size: 0.9rem; margin-right: 0.5rem;">
            Hoş geldin, {{ session.full_name if session.full_name else session.username }}!
          </span>
          
          <!-- Logout Button -->
          <a href="{{ url_for('logout') }}" style="padding: 8px 12px; background: #ef4444; color: white; text-decoration: none; border-radius: 6px; font-weight: 600; font-size: 0.9rem;">Çıkış</a>
          
          <!-- Dark Mode Toggle -->
          <button id="themeToggle" style="all: unset; cursor: pointer; padding: 0.5rem; border-radius: 0.5rem; display: flex; align-items: center; justify-content: center; background: var(--hover); border: 1px solid transparent;" title="Dark/Light Mode Toggle">
            <span id="themeIcon" style="font-size: 1.2rem;">🌙</span>
          </button>
          
          <nav class="hamburger" aria-label="Menüyü aç/kapat">
            <button id="btnHamburger" aria-controls="topMenu" aria-expanded="false" title="Menü">
              <span class="kbd">≡</span>
            </button>
          </nav>
        </div>

        <nav id="topMenu" class="menu" aria-label="Ana menü">
          <!-- Multiquery -->
          <div class="menu-item" aria-expanded="false">
            {% if session.get('is_admin') or check_permission(session.get('user_id'), 'multiquery') %}
            <a href="/multiquery" class="menu-btn">Multiquery</a>
            {% else %}
            <a href="#" class="menu-btn" onclick="showPermissionAlert('multiquery')">Multiquery</a>
            {% endif %}
          </div>

          <!-- PostgreSQL Installation -->
          <div class="menu-item" aria-expanded="false">
            {% if session.get('is_admin') or check_permission(session.get('user_id'), 'pg_install') %}
            <a href="/pg_install" class="menu-btn">PostgreSQL Installation</a>
            {% else %}
            <a href="#" class="menu-btn" onclick="showPermissionAlert('pg_install')">PostgreSQL Installation</a>
            {% endif %}
          </div>

          <!-- Admin Panel -->
          <div class="menu-item" aria-expanded="false">
            {% if session.get('is_admin') or check_permission(session.get('user_id'), 'admin_panel') %}
            <a href="/admin" class="menu-btn">Admin Panel</a>
            {% else %}
            <a href="#" class="menu-btn" onclick="showPermissionAlert('admin_panel')">Admin Panel</a>
            {% endif %}
          </div>

          <!-- Envanter -->
          <div class="menu-item" aria-expanded="false">
            {% if session.get('is_admin') or check_permission(session.get('user_id'), 'multiquery') %}
            <a href="/envanter" class="menu-btn">Envanter</a>
            {% else %}
            <a href="#" class="menu-btn" onclick="showPermissionAlert('multiquery')">Envanter</a>
            {% endif %}
          </div>

          <!-- Healthcheck -->
          <div class="menu-item" aria-expanded="false">
            {% if session.get('is_admin') or check_permission(session.get('user_id'), 'multiquery') %}
            <a href="/healthcheck" class="menu-btn">Healthcheck</a>
            {% else %}
            <a href="#" class="menu-btn" onclick="showPermissionAlert('multiquery')">Healthcheck</a>
            {% endif %}
          </div>

          <!-- Faydalı Linkler -->
          <div class="menu-item" aria-expanded="false">
            {% if session.get('is_admin') or check_permission(session.get('user_id'), 'faydali_linkler') %}
            <button class="menu-btn" data-toggle>Faydalı Linkler<div class="caret"></div></button>
            <div class="dropdown">
              <!-- Ticket -->
              <div class="submenu-item">
                <a href="#" class="submenu-trigger">Ticket <span class="submenu-caret">›</span></a>
                <div class="submenu">
                  <a href="https://burganteknoloji.ebt.bank:8080/WOListView.do?viewID=301&globalViewName=All_Requests">Oluştur</a>
                  <a href="https://burganteknoloji.ebt.bank:8080/WOListView.do">Takip</a>
                  <a href="#/ticket/rapor">Rapor</a>
                </div>
              </div>
              
              <!-- CyberArk -->
              <div class="submenu-item">
                <a href="#" class="submenu-trigger">CyberArk <span class="submenu-caret">›</span></a>
                <div class="submenu">
                  <a href="https://10.180.99.83/PasswordVault/v10/logon/radius">Giriş</a>
                </div>
              </div>
              
              <!-- Monitor -->
              <div class="submenu-item">
                <a href="#" class="submenu-trigger">Monitor <span class="submenu-caret">›</span></a>
                <div class="submenu">
                  <a href="https://zbx.ebt.bank/index.php?request=zabbix.php%3Faction%3Dcharts.view%26filter_hostids%255B0%255D%3D10897%26filter_set%3D1">Zabbix</a>
                  <a href="https://burgandpa.ebt.bank/iwc/login.iwc">Solarwinds</a>
                  <a href="https://zbx.ebt.bank/index.php?request=zabbix.php%3Faction%3Ddashboard.view">Zabbix2</a>
                  <a href="https://burganmonitor.ebt.bank/Orion/Login.aspx?ReturnUrl=%2fapps%2fsearch%2f%3fq%3dSVPRDBNKDB0&q=SVPRDBNKDB0">Burgan Monitör</a>
                  <a href="https://intprod-pmm-ui.apps.bmprod.ebt.bank/graph/d/pmm-home/home-dashboard?orgId=1&refresh=1m">PMM Percona</a>
                </div>
              </div>
              
              <!-- QLIK -->
              <div class="submenu-item">
                <a href="#" class="submenu-trigger">QLIK <span class="submenu-caret">›</span></a>
                <div class="submenu">
                  <a href="https://qlikcls.ebt.bank/attunityreplicate/2023.5.0.322/#!/tasks">Prod</a>
                  <a href="https://svtstqlik01.ebt.bank/attunityreplicate/2023.5.0.322/#!/tasks">Test</a>
                  <a href="https://mybanknew.ebt.bank/ahy/Project%20Documents/Forms/AllItems.aspx?RootFolder=%2fahy%2fProject%20Documents%2fQLIK%2dMONITORING&FolderCTID=0x0120002EA23D566BB92F44BBE160C11D088F62">Döküman</a>
                  <a href="https://svprdqlik04.ebt.bank/attunityenterprisemanager/2023.5.0.285/#!/analytics/trends#t1741157668863">Enterprise Manager</a>
                </div>
              </div>
              
              <!-- VDP - ACTIFIO -->
              <div class="submenu-item">
                <a href="#" class="submenu-trigger">VDP <span class="submenu-caret">›</span></a>
                <div class="submenu">
                  <a href="https://10.180.20.230/#globalworkflows/offset=0&limit=25">VDP</a>
                  <a href="https://10.180.20.76/#hostedit/4581560">OLD ACTIFIO</a>
                </div>
              </div>
              
              <!-- OpenShift -->
              <div class="submenu-item">
                <a href="#" class="submenu-trigger">OpenShift <span class="submenu-caret">›</span></a>
                <div class="submenu">
                  <a href="https://oauth-openshift.apps.nonprod.ebt.bank/oauth/authorize?client_id=console&redirect_uri=https%3A%2F%2Fconsole-openshift-console.apps.nonprod.ebt.bank%2Fauth%2Fcallback&response_type=code&scope=user%3Afull&state=b52e7628">Test</a>
                  <a href="https://console-openshift-console.apps.intprod.ebt.bank/add/all-namespaces">Prod</a>
                  <a href="https://console-openshift-console.apps.sasviyaprod.ebt.bank/k8s/cluster/projects">SasViya Prod</a>
                  <a href="https://console-openshift-console.apps.sasviyanonprod.ebt.bank/k8s/cluster/projects">SasViya Test</a>
                  <a href="https://svprdansible01.ebt.bank/#/login">Ansible Tower</a>
                  <a href="#/ocp/labs">Labs / Test</a>
                </div>
              </div>
              
              <!-- Talep Sistemi -->
              <div class="submenu-item">
                <a href="#" class="submenu-trigger">Talep Sistemi <span class="submenu-caret">›</span></a>
                <div class="submenu">
                  <a href="https://burganteknoloji.ebt.bank:8080/WorkOrder.do?woMode=newWO&reqTemplate=15905">SQL User Yetkilendirme</a>
                  <a href="https://burganteknoloji.ebt.bank:8080/WorkOrder.do?woMode=newWO&reqTemplate=15905">SQL Script Geçilmesi</a>
                  <a href="https://burganteknoloji.ebt.bank:8080/WorkOrder.do?woMode=newWO&reqTemplate=15906">Oracle User Talebi</a>
                  <a href="https://burganteknoloji.ebt.bank:8080/WorkOrder.do?woMode=newWO&reqTemplate=15910">Postgresql User Talebi</a>
                  <a href="https://burganteknoloji.ebt.bank:8080/WorkOrder.do?woMode=newWO&reqTemplate=16501">Postgresql Script Talebi</a>
                  <a href="https://burganteknoloji.ebt.bank:8080/WorkOrder.do?woMode=newWO&reqTemplate=21001&requestServiceId=331">Sunucu Kaynak Artırım</a>
                  <a href="https://tfs.burgan.com.tr/tfs/DefaultCollection/Talep%20Y%C3%B6netimi/_workitems/create/DataUpdate">Data Update Devops</a>
                  <a href="https://tfs.burgan.com.tr/tfs/DefaultCollection/Talep%20Y%C3%B6netimi/_workitems/create/DBAManuelScript">Data Manuel Script</a>
                  <a href="https://burganteknoloji.ebt.bank:8080/WorkOrder.do?woMode=newWO&reqTemplate=21321&requestServiceId=329">Backup Restore</a>
                  <a href="https://burganteknoloji.ebt.bank:8080/WorkOrder.do?woMode=newWO&reqTemplate=21322">Bakım Performans</a>
                  <a href="https://burganteknoloji.ebt.bank:8080/WorkOrder.do?woMode=newWO&reqTemplate=21323">Kurulum</a>
                  <a href="https://burganteknoloji.ebt.bank:8080/WorkOrder.do?woMode=newWO&reqTemplate=21324">DB Konfigurasyon</a>
                  <a href="https://burganteknoloji.ebt.bank:8080/WorkOrder.do?woMode=newWO&reqTemplate=4564&requestServiceId=329">Database Oluşturma</a>
                </div>
              </div>
              
              <!-- TFS -->
              <div class="submenu-item">
                <a href="#" class="submenu-trigger">TFS <span class="submenu-caret">›</span></a>
                <div class="submenu">
                  <a href="https://tfs.burgan.com.tr/tfs/DefaultCollection/Talep%20Y%C3%B6netimi/_queries/query/8a66c921-3e32-4061-9024-626453d9b203">Onay</a>
                  <a href="https://tfs.burgan.com.tr/tfs/DefaultCollection/Talep%20Y%C3%B6netimi/_queries/query/1ec4fd47-645f-48b4-8ffc-f205c963afe3/">TFS</a>
                  <a href="https://tfs.burgan.com.tr/tfs/DefaultCollection/EBT_PG_YBP_2.0/_release?_a=releases&view=mine&definitionId=57">Release</a>
                </div>
              </div>
              
              <!-- PGadmin -->
              <div class="submenu-item">
                <a href="#" class="submenu-trigger">PGadmin <span class="submenu-caret">›</span></a>
                <div class="submenu">
                  <a href="https://test-veriyonetimi-pgadmin.apps.nonprod.ebt.bank/browser/">Test</a>
                  <a href="https://intprod-veriyonetimi-pgadmin.apps.intprod.ebt.bank/browser/">Prod</a>
                </div>
              </div>
              
              <!-- Azure Arc -->
              <div class="submenu-item">
                <a href="#" class="submenu-trigger">Azure Arc <span class="submenu-caret">›</span></a>
                <div class="submenu">
                  <a href="https://portal.azure.com/#view/Microsoft_Azure_ArcCenterUX/ArcCenterMenuBlade/~/allresources/menuItem/allresources/menuParameters~/%7B%22view%22%3A%7B%22filter%22%3A%22%22%2C%22version%22%3A%221.0%22%2C%22sortedColumns%22%3A%5B%5D%2C%22showAll%22%3Afalse%2C%22gridColumns%22%3A%5B%7B%22id%22%3A%22name%22%2C%22name%22%3A%22name%22%2C%22visible%22%3Atrue%7D%2C%7B%22id%22%3A%22resourceGroup%22%2C%22name%22%3A%22resourceGroup%22%2C%22visible%22%3Atrue%7D%2C%7B%22id%22%3A%22location%22%2C%22name%22%3A%22location%22%2C%22visible%22%3Atrue%7D%2C%7B%22id%22%3A%22subscription%22%2C%22name%22%3A%22subscription%22%2C%22visible%22%3Atrue%7D%2C%7B%22id%22%3A%22assetType%22%2C%22name%22%3A%22assetType%22%2C%22visible%22%3Atrue%7D%5D%2C%22gridColumnWidths%22%3A%7B%22name%22%3A%22100fr%22%2C%22resourceGroup%22%3A%22100fr%22%2C%22location%22%3A%22100fr%22%2C%22subscription%22%3A%22100fr%22%2C%22assetType%22%3A%22100fr%22%7D%2C%22filterFacets%22%3A%5B%5D%7D%7D">Azure Arc</a>
                </div>
              </div>
            </div>
            {% else %}
            <a href="#" class="menu-btn" onclick="showPermissionAlert('faydali_linkler')">Faydalı Linkler</a>
            {% endif %}
          </div>
        </nav>
      </div>
    </header>

    <!-- Main content -->
    <main>
      <section class="panel">
        <div class="grid">
          <div class="col-8">
            <h2 id="pageTitle">Hoş geldin 👋</h2>
            <div id="pageBody" class="muted">
              Management Sistemine hoşgeldiniz.
               </div>
          <aside class="col-4">
            <div class="card">
              <h3>Hızlı İpuçları</h3>
              <ul class="muted">
                <li>  Multiquery giriş yapmadan önce DİKKAT EDİNİZ!!!  her sorgu bütün sunucularda çalıştırılacaktır. </li>
                <li> Multiquery ile postgresql sunucularında sorgular çalıştırılıp sonucunu excele alabilirsiniz.  </li>
              </ul>
            </div>
          </aside>
        </div>
      </section>
    </main>

    <footer class="footer">© <span id="year"></span> PostgreSQL Management System • FARUK ERDEM</footer>
  </div>

  <script>
    // Basit hash-router
    const PAGES = {};
    function registerPage(path, title, html){ PAGES[path] = {title, html}; }

    // ---- Multiquery PANEL: /multiquery butonuna gider ----
    registerPage('/multiquery/panel','Multiquery • Panel', `
      <div class="card">
        <h3>Multiquery Modülü</h3>
        <p class="muted">Birden fazla PostgreSQL sunucusunda eşzamanlı sorgu çalıştırmak için modülü aç.</p>
        <a class="btn" href="/multiquery">Multiquery’i Aç</a>
      </div>
    `);

    // Örnek sayfalar
    registerPage('/monitor/link1','Monitor • 1. Link', `
      <p class="muted">Buraya gözlem panelleri veya gömülü grafikleri ekleyebilirsin.</p>
      <div class="card"><h3>Node Durumu</h3><p class="muted">Patroni/HAProxy/Consul sağlık özetleri…</p></div>
    `);
    registerPage('/monitor/link2','Monitor • 2. Link', `<div class="card"><h3>WAL & Replikasyon</h3><p class="muted">Lag, slotlar, archive durumu…</p></div>`);
    registerPage('/monitor/link3','Monitor • 3. Link', `<div class="card"><h3>Sorgu Analizi</h3><p class="muted">pg_stat_statements özetleri…</p></div>`);

    registerPage('/qlik/prod','QLIK Prod', `<p>Prod QLIK paneline <a href="https://example.com" target="_blank">buradan</a> gidebilirsin.</p>`);
    registerPage('/qlik/test','QLIK Test', `<p>Test ortamı linkleri…</p>`);

    registerPage('/ocp/test','OpenShift Test', `<p>Test cluster erişimleri ve login yönergeleri…</p>`);
    registerPage('/ocp/prod','OpenShift Prod', `<p>Prod cluster bağlantı detayları…</p>`);

    registerPage('/talep/yeni','Talep Oluştur', `<p>Yeni istek formu taslağı…</p>`);

    registerPage('/tfs/onay','TFS • Onay', `<p>Onay bekleyen itemlar…</p>`);
    registerPage('/notes/hizli','Hızlı Notlar', `<ul class="muted"><li>SSH: <span class="kbd">ssh user@host</span></li><li>PG: <span class="kbd">psql -h …</span></li></ul>`);

    registerPage('/arc/env','Azure Arc Envanter', `<p>Arc’a kayıtlı sunucuların listesi ve arama filtresi…</p>`);

    // Router
    function render(){
      const hash = location.hash.replace(/^#/, '') || '/';
      const page = PAGES[hash];
      const titleEl = document.getElementById('pageTitle');
      const bodyEl  = document.getElementById('pageBody');
      if(page){ titleEl.textContent = page.title; bodyEl.innerHTML = page.html; }
      else if(hash !== '/') { titleEl.textContent = ''; bodyEl.innerHTML = '<p class="muted"></p>'; }
      document.title = (page? page.title + ' — ' : '') + 'PostgreSQL Management System';
    }
    window.addEventListener('hashchange', render);
    window.addEventListener('load', () => { render(); document.getElementById('year').textContent = new Date().getFullYear(); });

    // Mobile menü ve dokunmatik dropdown
    const btnHamburger = document.getElementById('btnHamburger');
    const topMenu = document.getElementById('topMenu');
    if(btnHamburger){
      btnHamburger.addEventListener('click', () => {
        const open = topMenu.classList.toggle('open');
        btnHamburger.setAttribute('aria-expanded', open);
      });
    }
    document.querySelectorAll('[data-toggle]').forEach(btn =>{
      const item = btn.closest('.menu-item');
      btn.addEventListener('click', (e)=>{
        if(window.matchMedia('(max-width:980px)').matches){
          const expanded = item.getAttribute('aria-expanded') === 'true';
          document.querySelectorAll('.menu-item').forEach(i=> i.setAttribute('aria-expanded','false'));
          item.setAttribute('aria-expanded', String(!expanded));
          e.stopPropagation();
        }
      });
    });
    document.addEventListener('click', ()=>{
      if(window.matchMedia('(max-width:980px)').matches){
        document.querySelectorAll('.menu-item').forEach(i=> i.setAttribute('aria-expanded','false'));
      }
    });

    // Submenu functionality
    document.querySelectorAll('.submenu-trigger').forEach(trigger => {
      trigger.addEventListener('click', function(e) {
        e.preventDefault();
        const submenuItem = this.closest('.submenu-item');
        const submenu = submenuItem.querySelector('.submenu');
        const isOpen = submenu.style.display === 'block';
        
        // Close all other submenus
        document.querySelectorAll('.submenu').forEach(s => s.style.display = 'none');
        
        // Toggle current submenu
        submenu.style.display = isOpen ? 'none' : 'block';
      });
    });

    // Close submenus when clicking outside
    document.addEventListener('click', function(e) {
      if (!e.target.closest('.submenu-item')) {
        document.querySelectorAll('.submenu').forEach(s => s.style.display = 'none');
      }
    });

    // Dark Mode Toggle
    function initTheme() {
      const savedTheme = localStorage.getItem('theme') || 'dark';
      const prefersDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
      const theme = savedTheme === 'dark' || (savedTheme === 'auto' && prefersDark) ? 'dark' : 'light';
      
      document.documentElement.setAttribute('data-theme', theme);
      
      const themeIcon = document.getElementById('themeIcon');
      if (themeIcon) {
        themeIcon.textContent = theme === 'dark' ? '🌙' : '☀️';
      }
      
      localStorage.setItem('theme', theme);
    }

    function toggleTheme() {
      const currentTheme = document.documentElement.getAttribute('data-theme');
      const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
      
      document.documentElement.setAttribute('data-theme', newTheme);
      
      const themeIcon = document.getElementById('themeIcon');
      if (themeIcon) {
        themeIcon.textContent = newTheme === 'dark' ? '🌙' : '☀️';
      }
      
      localStorage.setItem('theme', newTheme);
    }

    // Initialize theme on page load
    initTheme();

    // Add click event to theme toggle
    const themeToggle = document.getElementById('themeToggle');
    if (themeToggle) {
      themeToggle.addEventListener('click', toggleTheme);
    }
    
    // Yetki uyarı mesajı göster
    function showPermissionAlert(pageName) {
      const pageNames = {
        'multiquery': 'Multiquery',
        'pg_install': 'PostgreSQL Installation',
        'admin_panel': 'Admin Panel',
        'faydali_linkler': 'Faydalı Linkler'
      };
      
      const pageDisplayName = pageNames[pageName] || pageName;
      alert(`Yetkiniz yok! ${pageDisplayName} sayfasına erişim yetkiniz bulunmamaktadır. Faruk Erdem'e tatlı ısmarlayın 😊`);
    }

  </script>
  
  {{ theme_script|safe }}
</body>
</html>
"""

# Multiquery ana ekranı
TEMPLATE_INDEX = r"""
<!doctype html>
<html lang="tr">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{{ title }}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
      :root {
        --bg: #0f1216; --panel: #171b21; --muted: #9aa5b1; --txt: #eef2f6; --brand: #50b0ff; --accent: #7cf; --ring: rgba(80,176,255,.35);
        --drop: #0f1216; --hover: #212833;
      }
      
      /* Light mode variables */
      [data-theme="light"] {
        --bg: #f8fafc; --panel: #ffffff; --muted: #64748b; --txt: #1e293b; --brand: #3b82f6; --accent: #06b6d4; --ring: rgba(59,130,246,.35);
        --drop: #ffffff; --hover: #f1f5f9;
      }
      
      /* Dark mode variables */
      [data-theme="dark"] {
        --bg: #0f1216; --panel: #171b21; --muted: #9aa5b1; --txt: #eef2f6; --brand: #50b0ff; --accent: #7cf; --ring: rgba(80,176,255,.35);
        --drop: #0f1216; --hover: #212833;
      }
      
      body { 
        padding-top: 20px; 
        background: var(--bg); 
        color: var(--txt);
        font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif;
      }
      
      [data-theme="dark"] body { background: linear-gradient(180deg, #0c0f13, #0f1216); }
      [data-theme="light"] body { background: linear-gradient(180deg, #f1f5f9, #f8fafc); }
      
      .container-lg { background: var(--panel); border-radius: 1rem; padding: 2rem; margin-top: 1rem; border: 1px solid; }
      [data-theme="dark"] .container-lg { border-color: #242b37; }
      [data-theme="light"] .container-lg { border-color: #e2e8f0; }
      
      .card { background: var(--panel); border: 1px solid; }
      [data-theme="dark"] .card { border-color: #243044; }
      [data-theme="light"] .card { border-color: #e2e8f0; }
      
      .form-control, .form-select { background: var(--panel); color: var(--txt); border: 1px solid; }
      [data-theme="dark"] .form-control, .form-select { border-color: #243044; }
      [data-theme="light"] .form-control, .form-select { border-color: #e2e8f0; }
      
      .form-control:focus, .form-select:focus { background: var(--panel); color: var(--txt); border-color: var(--brand); box-shadow: 0 0 0 0.2rem var(--ring); }
      
      .table { color: var(--txt); }
      .table-striped > tbody > tr:nth-of-type(odd) > td { background: var(--hover); }
      
      .code { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; }
      .table-wrap { max-height: 420px; overflow: auto; }
      .sticky-th th { position: sticky; top: 0; background: var(--bs-body-bg); z-index: 1; }
      
      .btn-primary { background: var(--brand); border-color: var(--brand); }
      .btn-primary:hover { background: var(--accent); border-color: var(--accent); }
      .btn-success { background: #10b981; border-color: #10b981; }
      .btn-outline-danger { color: #ef4444; border-color: #ef4444; }
      .btn-outline-danger:hover { background: #ef4444; border-color: #ef4444; }
      .btn-outline-primary { color: var(--brand); border-color: var(--brand); }
      .btn-outline-primary:hover { background: var(--brand); border-color: var(--brand); }
      .btn-outline-secondary { color: var(--muted); border-color: var(--muted); }
      .btn-outline-secondary:hover { background: var(--muted); border-color: var(--muted); }
      
      .alert { border: 1px solid; }
      .alert-success { background: rgba(16, 185, 129, 0.1); border-color: #10b981; color: #10b981; }
      .alert-danger { background: rgba(239, 68, 68, 0.1); border-color: #ef4444; color: #ef4444; }
      .alert-warning { background: rgba(245, 158, 11, 0.1); border-color: #f59e0b; color: #f59e0b; }
      .alert-info { background: rgba(59, 130, 246, 0.1); border-color: #3b82f6; color: #3b82f6; }
      
      /* Modal */
      .modal-content { background: var(--panel); border: 1px solid; }
      [data-theme="dark"] .modal-content { border-color: #243044; }
      [data-theme="light"] .modal-content { border-color: #e2e8f0; }
      
      .modal-header { border-bottom: 1px solid; }
      [data-theme="dark"] .modal-header { border-color: #243044; }
      [data-theme="light"] .modal-header { border-color: #e2e8f0; }
      
      .modal-footer { border-top: 1px solid; }
      [data-theme="dark"] .modal-footer { border-color: #243044; }
      [data-theme="light"] .modal-footer { border-color: #e2e8f0; }
      
      .btn-close { filter: invert(1); }
      [data-theme="light"] .btn-close { filter: invert(0); }
      
      /* Theme Toggle Button */
      #themeToggle { all: unset; cursor: pointer; padding: 0.5rem; border-radius: 0.5rem; display: flex; align-items: center; justify-content: center; background: var(--hover); border: 1px solid transparent; margin-left: auto; }
      #themeToggle:hover { background: var(--hover); border-color: var(--brand); }
      [data-theme="dark"] #themeToggle:hover { border-color: #50b0ff; }
      [data-theme="light"] #themeToggle:hover { border-color: #3b82f6; }
      
      /* Multiquery specific fixes */
      .card-header { background: var(--hover); color: var(--txt); border-bottom: 1px solid; }
      [data-theme="dark"] .card-header { border-color: #243044; }
      [data-theme="light"] .card-header { border-color: #e2e8f0; }
      
      .form-label { color: var(--txt); font-weight: 600; }
      
      /* Table fixes */
      .table th { background: var(--hover); color: var(--txt); border-color: var(--hover); }
      .table td { color: var(--txt); border-color: var(--hover); }
      
      /* Badge fixes */
      .badge { background: var(--hover); color: var(--txt); }
      .badge-wrap .badge { background: var(--hover); color: var(--txt); border: 1px solid var(--hover); }
      
      /* Code fixes */
      code { background: var(--hover); color: var(--txt); padding: 0.25rem 0.5rem; border-radius: 0.25rem; }
      
      /* Modal title fixes */
      .modal-title { color: var(--txt); }
      
      /* Text color fixes */
      p, div, span, td, th, label, h1, h2, h3, h4, h5, h6 { color: var(--txt); }
      .text-muted { color: var(--muted) !important; }
    </style>
  </head>
  <body>
    <div class="container-lg">
      <div class="d-flex align-items-center mb-3">
        <h1 class="mb-0">{{ title }}</h1>
        <div style="display: flex; align-items: center; gap: 1rem; margin-left: auto;">
          <a href="/" style="padding: 8px 16px; background: #6b7280; color: white; text-decoration: none; border-radius: 6px; font-weight: 600;">← Ana Sayfa</a>
          <button id="themeToggle" title="Dark/Light Mode Toggle">
            <span id="themeIcon" style="font-size: 1.2rem;">🌙</span>
          </button>
        </div>
      </div>

      {% with messages = get_flashed_messages(with_categories=true) %}
        {% if messages %}
          {% for category, message in messages %}
            <div class="alert alert-{{ category }} alert-dismissible fade show" role="alert">
              {{ message }}
              <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
            </div>
          {% endfor %}
        {% endif %}
      {% endwith %}

      <div class="row g-4">
        <div class="col-12 col-xl-4">
          <div class="card shadow-sm">
            <div class="card-header">Sunucu Ekle</div>
            <div class="card-body">
              <form method="post" action="{{ url_for('add_server') }}" class="row g-2">
                <div class="col-12"><label class="form-label">Görünen Ad*</label><input name="name" class="form-control" placeholder="Prod-1 / Test-DB" required></div>
                <div class="col-8"><label class="form-label">Host/IP*</label><input name="host" class="form-control" placeholder="10.0.0.10" required></div>
                <div class="col-4"><label class="form-label">Port</label><input name="port" type="number" value="5432" class="form-control"></div>
                <div class="col-6"><label class="form-label">Veritabanı*</label><input name="dbname" class="form-control" placeholder="postgres" required></div>
                <div class="col-6"><label class="form-label">Kullanıcı*</label><input name="username" class="form-control" placeholder="postgres" required></div>
                <div class="col-12"><label class="form-label">Parola*</label><input name="password" type="password" class="form-control" required></div>
                <div class="col-12 text-end pt-2"><button class="btn btn-primary">Ekle</button></div>
              </form>
            </div>
          </div>
        </div>

        <!-- Edit Server Modal -->
        <div class="modal fade" id="editServerModal" tabindex="-1" aria-labelledby="editServerModalLabel" aria-hidden="true">
          <div class="modal-dialog">
            <div class="modal-content">
              <div class="modal-header">
                <h5 class="modal-title" id="editServerModalLabel">Sunucu Düzenle</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
              </div>
              <form id="editServerForm" method="post" action="{{ url_for('edit_server') }}">
                <div class="modal-body">
                  <input type="hidden" id="edit_server_id" name="edit_server_id">
                  <div class="row g-2">
                    <div class="col-12">
                      <label class="form-label">Görünen Ad*</label>
                      <input id="edit_name" name="edit_name" class="form-control" placeholder="Prod-1 / Test-DB" required>
                    </div>
                    <div class="col-8">
                      <label class="form-label">Host/IP*</label>
                      <input id="edit_host" name="edit_host" class="form-control" placeholder="10.0.0.10" required>
                    </div>
                    <div class="col-4">
                      <label class="form-label">Port</label>
                      <input id="edit_port" name="edit_port" type="number" value="5432" class="form-control">
                    </div>
                    <div class="col-6">
                      <label class="form-label">Veritabanı*</label>
                      <input id="edit_dbname" name="edit_dbname" class="form-control" placeholder="postgres" required>
                    </div>
                    <div class="col-6">
                      <label class="form-label">Kullanıcı*</label>
                      <input id="edit_username" name="edit_username" class="form-control" placeholder="postgres" required>
                    </div>
                    <div class="col-12">
                      <label class="form-label">Parola*</label>
                      <input id="edit_password" name="edit_password" type="password" class="form-control" placeholder="Mevcut parola değiştirilmezse boş bırakın">
                    </div>
                  </div>
                </div>
                <div class="modal-footer">
                  <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">İptal</button>
                  <button type="submit" class="btn btn-primary">Kaydet</button>
                </div>
              </form>
            </div>
          </div>
        </div>

        <div class="col-12 col-xl-8">
          <div class="card shadow-sm">
            <div class="card-header d-flex justify-content-between align-items-center">
              <span>Sunucu Listesi ve Sorgu</span>
              <small class="text-muted">Timeout: {{ STMT_TIMEOUT_MS }} ms · Max satır: {{ MAX_ROWS }}</small>
            </div>
            <div class="card-body">
              <form method="post" action="{{ url_for('run_query') }}">
                <div class="mb-3">
                  <label class="form-label">SQL</label>
                  <div class="mb-2">
                    <button type="button" class="btn btn-success btn-sm" onclick="openAIAssistant()">
                      🤖 AI Sorgu Asistanı
                    </button>
                    <button type="button" class="btn btn-secondary btn-sm" onclick="clearSQL()">
                      🗑️ Temizle
                    </button>
                  </div>
                  <textarea id="sqlTextarea" name="sql" class="form-control code" rows="6" placeholder="SELECT version();" required>SELECT version();</textarea>
                </div>

                <div class="mb-2 d-flex justify-content-between align-items-center">
                  <div class="form-check">
                    <input class="form-check-input" type="checkbox" id="selectAll" onclick="toggleAll(this)">
                    <label class="form-check-label" for="selectAll">Tümünü Seç / Kaldır</label>
                  </div>
                  <a href="{{ url_for('load_inventory_servers') }}" class="btn btn-warning btn-sm">
                    📦 Envanterden Sunucuları Çek
                  </a>
                </div>

                <div class="table-responsive">
                  <table class="table table-sm align-middle">
                    <thead class="table-light sticky-th">
                      <tr>
                        <th style="width:40px"></th>
                        <th>Ad</th>
                        <th>Host</th>
                        <th>Port</th>
                        <th>DB</th>
                        <th>Kullanıcı</th>
                        <th class="text-end">Sil</th>
                      </tr>
                    </thead>
                    <tbody>
                      {% for s in servers %}
                      <tr onclick="toggleServerCheckbox('{{ s.id }}')" style="cursor: pointer;">
                        <td><input class="form-check-input" type="checkbox" name="server_id" value="{{ s.id }}" id="server_{{ s.id }}" onclick="event.stopPropagation();"></td>
                        <td>{{ s.name }}</td>
                        <td class="code">{{ s.host }}</td>
                        <td>{{ s.port }}</td>
                        <td>{{ s.dbname }}</td>
                        <td>{{ s.username }}</td>
                        <td class="text-end">
                          {% if s.get('is_inventory') %}
                            <span class="badge bg-info text-dark">Envanter</span>
                          {% else %}
                            <button class="btn btn-outline-primary btn-sm me-1" type="button" onclick="editServer(event, {{ s.id }}, '{{ s.name }}', '{{ s.host }}', {{ s.port }}, '{{ s.dbname }}', '{{ s.username }}')">Düzenle</button>
                            <button class="btn btn-outline-danger btn-sm" formmethod="post" formaction="{{ url_for('delete_server', sid=s.id) }}" formnovalidate onclick="return confirm('Silinsin mi?');">Sil</button>
                          {% endif %}
                        </td>
                      </tr>
                      {% else %}
                      <tr><td colspan="7" class="text-muted">Henüz sunucu yok. Soldan ekleyin.</td></tr>
                      {% endfor %}
                    </tbody>
                  </table>
                </div>

                <div class="text-end"><button class="btn btn-success">Sorguyu Çalıştır</button></div>
              </form>
            </div>
          </div>
        </div>
      </div>

      <script>
      function toggleAll(cb){
        document.querySelectorAll('input[name="server_id"]').forEach(x => x.checked = cb.checked);
      }

      function toggleServerCheckbox(serverId) {
        const checkbox = document.getElementById('server_' + serverId);
        if (checkbox) {
          checkbox.checked = !checkbox.checked;
        }
      }

      function editServer(event, id, name, host, port, dbname, username) {
        // Checkbox seçimini etkilememek için event'i durdur
        event.stopPropagation();
        event.preventDefault();
        
        document.getElementById('edit_server_id').value = id;
        document.getElementById('edit_name').value = name;
        document.getElementById('edit_host').value = host;
        document.getElementById('edit_port').value = port;
        document.getElementById('edit_dbname').value = dbname;
        document.getElementById('edit_username').value = username;
        document.getElementById('edit_password').value = '';
        
        const modal = new bootstrap.Modal(document.getElementById('editServerModal'));
        modal.show();
      }

      // Dark Mode Toggle
      function initTheme() {
        const savedTheme = localStorage.getItem('theme') || 'dark';
        const prefersDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
        const theme = savedTheme === 'dark' || (savedTheme === 'auto' && prefersDark) ? 'dark' : 'light';
        
        document.documentElement.setAttribute('data-theme', theme);
        
        const themeIcon = document.getElementById('themeIcon');
        if (themeIcon) {
          themeIcon.textContent = theme === 'dark' ? '🌙' : '☀️';
        }
        
        localStorage.setItem('theme', theme);
      }

      function toggleTheme() {
        const currentTheme = document.documentElement.getAttribute('data-theme');
        const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
        
        document.documentElement.setAttribute('data-theme', newTheme);
        
        const themeIcon = document.getElementById('themeIcon');
        if (themeIcon) {
          themeIcon.textContent = newTheme === 'dark' ? '🌙' : '☀️';
        }
        
        localStorage.setItem('theme', newTheme);
      }

      // Initialize theme on page load
      initTheme();

      // Add click event to theme toggle
      const themeToggle = document.getElementById('themeToggle');
      if (themeToggle) {
        themeToggle.addEventListener('click', toggleTheme);
      }
      
      // AI Assistant functions
      function openAIAssistant() {
        // Geliştirme aşamasında uyarı
        if (confirm('⚠️ AI Sorgu Asistanı Geliştirme Aşamasındadır!\n\n🤖 Üretilen sorguları mutlaka kontrol ediniz.\n📝 Sorgular doğruluğu garanti edilmez.\n🔍 Çalıştırmadan önce SQL\'i gözden geçirin.\n\nDevam etmek istiyor musunuz?')) {
          document.getElementById('aiAssistantModal').style.display = 'block';
        }
      }
      
      function closeAIAssistant() {
        document.getElementById('aiAssistantModal').style.display = 'none';
      }
      
      function clearSQL() {
        document.getElementById('sqlTextarea').value = '';
      }
      
      function generateSQL() {
        const prompt = document.getElementById('aiPrompt').value.trim();
        if (!prompt) {
          alert('Lütfen bir istek yazın!');
          return;
        }
        
        // Basit prompt tabanlı SQL üretimi
        const sql = generateSQLFromPrompt(prompt);
        document.getElementById('sqlTextarea').value = sql;
        closeAIAssistant();
      }
      
      function generateSQLFromPrompt(prompt) {
        const lowerPrompt = prompt.toLowerCase();
        
        // PostgreSQL Replication komutları
        if (lowerPrompt.includes('replication') || lowerPrompt.includes('replikasyon') || lowerPrompt.includes('replica')) {
          if (lowerPrompt.includes('slot') || lowerPrompt.includes('slots')) {
            return 'SELECT slot_name, plugin, slot_type, database, active, xmin, catalog_xmin, restart_lsn, confirmed_flush_lsn FROM pg_replication_slots;';
          } else if (lowerPrompt.includes('stat') || lowerPrompt.includes('durum') || lowerPrompt.includes('status')) {
            return 'SELECT client_addr, application_name, state, sync_state, sync_priority, replay_lag FROM pg_stat_replication;';
          } else if (lowerPrompt.includes('lag') || lowerPrompt.includes('gecikme')) {
            return 'SELECT client_addr, application_name, state, sync_state, replay_lag, write_lag, flush_lag FROM pg_stat_replication;';
          } else {
            return '-- PostgreSQL Replication Bilgileri\nSELECT \'Replication Slots\' as bilgi, COUNT(*) as sayi FROM pg_replication_slots\nUNION ALL\nSELECT \'Active Replications\' as bilgi, COUNT(*) as sayi FROM pg_stat_replication;';
          }
        }
        
        // Database işlemleri
        if (lowerPrompt.includes('database') || lowerPrompt.includes('veritabanı') || lowerPrompt.includes('db')) {
          if (lowerPrompt.includes('list') || lowerPrompt.includes('liste')) {
            return 'SELECT datname as database_name, datowner, encoding, datcollate, datctype, datacl FROM pg_database;';
          } else if (lowerPrompt.includes('size') || lowerPrompt.includes('boyut')) {
            return 'SELECT datname, pg_size_pretty(pg_database_size(datname)) as size FROM pg_database ORDER BY pg_database_size(datname) DESC;';
          } else if (lowerPrompt.includes('connection') || lowerPrompt.includes('bağlantı')) {
            return 'SELECT datname, numbackends, xact_commit, xact_rollback, blks_read, blks_hit FROM pg_stat_database;';
          }
        }
        
        // Table işlemleri
        if (lowerPrompt.includes('table') || lowerPrompt.includes('tablo')) {
          if (lowerPrompt.includes('list') || lowerPrompt.includes('liste')) {
            return 'SELECT schemaname, tablename, tableowner, hasindexes, hasrules, hastriggers FROM pg_tables WHERE schemaname = \'public\';';
          } else if (lowerPrompt.includes('size') || lowerPrompt.includes('boyut')) {
            return 'SELECT schemaname, tablename, pg_size_pretty(pg_total_relation_size(schemaname||\'.\'||tablename)) as size FROM pg_tables WHERE schemaname = \'public\';';
          } else if (lowerPrompt.includes('stat') || lowerPrompt.includes('istatistik')) {
            return 'SELECT schemaname, tablename, n_tup_ins, n_tup_upd, n_tup_del, n_live_tup, n_dead_tup FROM pg_stat_user_tables;';
          }
        }
        
        // Index işlemleri
        if (lowerPrompt.includes('index') || lowerPrompt.includes('indeks')) {
          if (lowerPrompt.includes('list') || lowerPrompt.includes('liste')) {
            return 'SELECT schemaname, tablename, indexname, indexdef FROM pg_indexes WHERE schemaname = \'public\';';
          } else if (lowerPrompt.includes('unused') || lowerPrompt.includes('kullanılmayan')) {
            return 'SELECT schemaname, tablename, indexrelname, idx_tup_read, idx_tup_fetch FROM pg_stat_user_indexes WHERE idx_tup_read = 0;';
          } else if (lowerPrompt.includes('size') || lowerPrompt.includes('boyut')) {
            return 'SELECT schemaname, tablename, indexname, pg_size_pretty(pg_relation_size(schemaname||\'.\'||indexname)) as size FROM pg_indexes WHERE schemaname = \'public\';';
          }
        }
        
        // User/Role işlemleri
        if (lowerPrompt.includes('user') || lowerPrompt.includes('kullanıcı') || lowerPrompt.includes('role')) {
          if (lowerPrompt.includes('list') || lowerPrompt.includes('liste')) {
            return 'SELECT rolname, rolsuper, rolinherit, rolcreaterole, rolcreatedb, rolcanlogin FROM pg_roles;';
          } else if (lowerPrompt.includes('privilege') || lowerPrompt.includes('yetki')) {
            return 'SELECT grantee, table_name, privilege_type FROM information_schema.table_privileges WHERE grantee != \'postgres\';';
          } else if (lowerPrompt.includes('connection') || lowerPrompt.includes('bağlantı')) {
            return 'SELECT usename, application_name, client_addr, state, query_start FROM pg_stat_activity WHERE usename IS NOT NULL;';
          }
        }
        
        // Locks ve Blocking
        if (lowerPrompt.includes('lock') || lowerPrompt.includes('kilitleme') || lowerPrompt.includes('block')) {
          if (lowerPrompt.includes('wait') || lowerPrompt.includes('bekleyen')) {
            return 'SELECT blocked_locks.pid AS blocked_pid, blocked_activity.usename AS blocked_user, blocking_locks.pid AS blocking_pid, blocking_activity.usename AS blocking_user, blocked_activity.query AS blocked_statement FROM pg_catalog.pg_locks blocked_locks JOIN pg_catalog.pg_stat_activity blocked_activity ON blocked_activity.pid = blocked_locks.pid JOIN pg_catalog.pg_locks blocking_locks ON blocking_locks.locktype = blocked_locks.locktype AND blocking_locks.database IS NOT DISTINCT FROM blocked_locks.database AND blocking_locks.relation IS NOT DISTINCT FROM blocked_locks.relation AND blocking_locks.page IS NOT DISTINCT FROM blocked_locks.page AND blocking_locks.tuple IS NOT DISTINCT FROM blocked_locks.tuple AND blocking_locks.virtualxid IS NOT DISTINCT FROM blocked_locks.virtualxid AND blocking_locks.transactionid IS NOT DISTINCT FROM blocked_locks.transactionid AND blocking_locks.classid IS NOT DISTINCT FROM blocked_locks.classid AND blocking_locks.objid IS NOT DISTINCT FROM blocked_locks.objid AND blocking_locks.objsubid IS NOT DISTINCT FROM blocked_locks.objsubid AND blocking_locks.pid != blocked_locks.pid JOIN pg_catalog.pg_stat_activity blocking_activity ON blocking_activity.pid = blocking_locks.pid WHERE NOT blocked_locks.granted;';
          } else {
            return 'SELECT mode, locktype, relation::regclass, pid, granted FROM pg_locks WHERE NOT granted;';
          }
        }
        
        // Performance ve Statistics
        if (lowerPrompt.includes('performance') || lowerPrompt.includes('performans') || lowerPrompt.includes('slow')) {
          if (lowerPrompt.includes('query') || lowerPrompt.includes('sorgu')) {
            return 'SELECT query, calls, total_time, mean_time, rows FROM pg_stat_statements ORDER BY total_time DESC LIMIT 10;';
          } else if (lowerPrompt.includes('table') || lowerPrompt.includes('tablo')) {
            return 'SELECT schemaname, tablename, seq_scan, seq_tup_read, idx_scan, idx_tup_fetch FROM pg_stat_user_tables ORDER BY seq_scan DESC LIMIT 10;';
          }
        }
        
        // Backup ve WAL
        if (lowerPrompt.includes('backup') || lowerPrompt.includes('yedek') || lowerPrompt.includes('wal')) {
          if (lowerPrompt.includes('wal') || lowerPrompt.includes('log')) {
            return 'SELECT pg_current_wal_lsn() as current_wal_lsn, pg_walfile_name(pg_current_wal_lsn()) as current_wal_file;';
          } else if (lowerPrompt.includes('archive') || lowerPrompt.includes('arşiv')) {
            return 'SHOW archive_mode;';
          }
        }
        
        // Configuration
        if (lowerPrompt.includes('config') || lowerPrompt.includes('ayar') || lowerPrompt.includes('setting')) {
          if (lowerPrompt.includes('memory') || lowerPrompt.includes('bellek') || lowerPrompt.includes('ram')) {
            return 'SELECT name, setting, unit FROM pg_settings WHERE name LIKE \'%memory%\' OR name LIKE \'%shared_buffers%\' OR name LIKE \'%work_mem%\';';
          } else if (lowerPrompt.includes('connection') || lowerPrompt.includes('bağlantı')) {
            return 'SELECT name, setting, unit FROM pg_settings WHERE name LIKE \'%connection%\' OR name LIKE \'%max_connections%\';';
          } else {
            return 'SELECT name, setting, unit, context FROM pg_settings WHERE context IN (\'postmaster\', \'sighup\') ORDER BY name;';
          }
        }
        
        // System Information
        if (lowerPrompt.includes('system') || lowerPrompt.includes('sistem') || lowerPrompt.includes('info')) {
          return 'SELECT version() as postgresql_version, current_database() as current_database, current_user as current_user, inet_server_addr() as server_ip, inet_server_port() as server_port;';
        }
        
        // Process ve Activity
        if (lowerPrompt.includes('process') || lowerPrompt.includes('process') || lowerPrompt.includes('activity')) {
          if (lowerPrompt.includes('long') || lowerPrompt.includes('uzun') || lowerPrompt.includes('running')) {
            return 'SELECT pid, usename, application_name, client_addr, state, query_start, query FROM pg_stat_activity WHERE state = \'active\' AND query_start < now() - interval \'5 minutes\';';
          } else {
            return 'SELECT pid, usename, application_name, client_addr, state, query_start, query FROM pg_stat_activity WHERE state = \'active\';';
          }
        }
        
        // Space ve Disk Usage
        if (lowerPrompt.includes('space') || lowerPrompt.includes('disk') || lowerPrompt.includes('alan')) {
          return 'SELECT schemaname, tablename, pg_size_pretty(pg_total_relation_size(schemaname||\'.\'||tablename)) as total_size, pg_size_pretty(pg_relation_size(schemaname||\'.\'||tablename)) as table_size FROM pg_tables WHERE schemaname = \'public\' ORDER BY pg_total_relation_size(schemaname||\'.\'||tablename) DESC;';
        }
        
        // Default queries for common terms
        if (lowerPrompt.includes('tüm') || lowerPrompt.includes('all') || lowerPrompt.includes('listele')) {
          if (lowerPrompt.includes('kullanıcı') || lowerPrompt.includes('user')) {
            return 'SELECT * FROM users;';
          } else if (lowerPrompt.includes('tablo') || lowerPrompt.includes('table')) {
            return 'SELECT table_name FROM information_schema.tables WHERE table_schema = \'public\';';
          } else if (lowerPrompt.includes('kolon') || lowerPrompt.includes('column')) {
            return 'SELECT column_name, data_type FROM information_schema.columns WHERE table_schema = \'public\';';
          }
        }
        
        if (lowerPrompt.includes('say') || lowerPrompt.includes('count')) {
          if (lowerPrompt.includes('kullanıcı') || lowerPrompt.includes('user')) {
            return 'SELECT COUNT(*) as kullanici_sayisi FROM users;';
          } else if (lowerPrompt.includes('tablo') || lowerPrompt.includes('table')) {
            return 'SELECT COUNT(*) as tablo_sayisi FROM information_schema.tables WHERE table_schema = \'public\';';
          }
        }
        
        if (lowerPrompt.includes('aktif') || lowerPrompt.includes('active')) {
          return 'SELECT * FROM users WHERE is_active = true;';
        }
        
        if (lowerPrompt.includes('admin') || lowerPrompt.includes('yönetici')) {
          return 'SELECT * FROM users WHERE is_admin = true;';
        }
        
        if (lowerPrompt.includes('versiyon') || lowerPrompt.includes('version')) {
          return 'SELECT version();';
        }
        
        if (lowerPrompt.includes('tarih') || lowerPrompt.includes('date')) {
          return 'SELECT NOW() as suanki_tarih;';
        }
        
        if (lowerPrompt.includes('boyut') || lowerPrompt.includes('size')) {
          return 'SELECT pg_database_size(current_database()) as veritabani_boyutu;';
        }
        
        if (lowerPrompt.includes('bağlantı') || lowerPrompt.includes('connection')) {
          return 'SELECT * FROM pg_stat_activity WHERE state = \'active\';';
        }
        
        // Genel PostgreSQL bilgi sorgusu
        return '-- PostgreSQL Sistem Bilgileri\nSELECT \'PostgreSQL Version\' as bilgi, version() as deger\nUNION ALL\nSELECT \'Current Database\' as bilgi, current_database() as deger\nUNION ALL\nSELECT \'Current User\' as bilgi, current_user as deger\nUNION ALL\nSELECT \'Server IP\' as bilgi, COALESCE(inet_server_addr()::text, \'Local\') as deger;';
      }
      
      // Theme Toggle Functions
      function initTheme() {
        const savedTheme = localStorage.getItem('theme');
        const prefersDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
        const theme = savedTheme || (prefersDark ? 'dark' : 'light');
        
        document.documentElement.setAttribute('data-theme', theme);
        
        const themeIcon = document.getElementById('themeIcon');
        if (themeIcon) {
          themeIcon.textContent = theme === 'dark' ? '☀️' : '🌙';
        }
      }
      
      function toggleTheme() {
        const currentTheme = document.documentElement.getAttribute('data-theme');
        const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
        
        document.documentElement.setAttribute('data-theme', newTheme);
        localStorage.setItem('theme', newTheme);
        
        const themeIcon = document.getElementById('themeIcon');
        if (themeIcon) {
          themeIcon.textContent = newTheme === 'dark' ? '☀️' : '🌙';
        }
      }
      
      // Initialize theme on page load
      document.addEventListener('DOMContentLoaded', function() {
        initTheme();
        
        // Add click event to theme toggle
        const themeToggle = document.getElementById('themeToggle');
        if (themeToggle) {
          themeToggle.addEventListener('click', toggleTheme);
        }
      });
      </script>
    </div>
    
    <!-- AI Assistant Modal -->
    <div id="aiAssistantModal" style="display: none; position: fixed; z-index: 1000; left: 0; top: 0; width: 100%; height: 100%; background-color: rgba(0,0,0,0.5);">
      <div style="background-color: var(--panel); margin: 5% auto; padding: 20px; border: 1px solid var(--muted); border-radius: 8px; width: 80%; max-width: 600px; color: var(--txt);">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
          <h3 style="margin: 0; color: var(--brand);">🤖 AI Sorgu Asistanı</h3>
          <button onclick="closeAIAssistant()" style="background: none; border: none; color: var(--muted); font-size: 24px; cursor: pointer;">&times;</button>
        </div>
        
        <!-- Geliştirme Aşaması Uyarısı -->
        <div style="background: var(--hover); border: 1px solid var(--muted); color: var(--txt); padding: 12px; border-radius: 4px; margin-bottom: 20px;">
          <div style="display: flex; align-items: center; gap: 8px;">
            <span style="font-size: 20px;">⚠️</span>
            <div>
              <strong>Geliştirme Aşamasında!</strong><br>
              <small>Üretilen sorguları mutlaka kontrol ediniz. Sorguların doğruluğu garanti edilmez.</small>
            </div>
          </div>
        </div>
        
        <div style="margin-bottom: 20px;">
          <label style="display: block; margin-bottom: 8px; font-weight: bold;">Ne yapmak istiyorsunuz?</label>
          <textarea id="aiPrompt" placeholder="Örnek: Tüm kullanıcıları listele, Aktif kullanıcıları say, Admin kullanıcıları göster, Veritabanı versiyonunu öğren..." 
                    style="width: 100%; padding: 12px; border: 1px solid var(--muted); border-radius: 4px; background: var(--bg); color: var(--txt); resize: vertical; min-height: 100px;"></textarea>
        </div>
        
        <div style="margin-bottom: 20px;">
          <h4 style="color: var(--brand); margin-bottom: 10px;">💡 Örnek İstekler:</h4>
          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px; font-size: 14px;">
            <div style="padding: 8px; background: var(--bg); border-radius: 4px; cursor: pointer;" onclick="document.getElementById('aiPrompt').value = 'PostgreSQL replication durumunu göster'">
              • PostgreSQL replication durumunu göster
            </div>
            <div style="padding: 8px; background: var(--bg); border-radius: 4px; cursor: pointer;" onclick="document.getElementById('aiPrompt').value = 'Tüm veritabanlarını listele'">
              • Tüm veritabanlarını listele
            </div>
            <div style="padding: 8px; background: var(--bg); border-radius: 4px; cursor: pointer;" onclick="document.getElementById('aiPrompt').value = 'Kullanılmayan indeksleri göster'">
              • Kullanılmayan indeksleri göster
            </div>
            <div style="padding: 8px; background: var(--bg); border-radius: 4px; cursor: pointer;" onclick="document.getElementById('aiPrompt').value = 'Bekleyen lockları göster'">
              • Bekleyen lockları göster
            </div>
            <div style="padding: 8px; background: var(--bg); border-radius: 4px; cursor: pointer;" onclick="document.getElementById('aiPrompt').value = 'Yavaş sorguları listele'">
              • Yavaş sorguları listele
            </div>
            <div style="padding: 8px; background: var(--bg); border-radius: 4px; cursor: pointer;" onclick="document.getElementById('aiPrompt').value = 'Disk kullanımını göster'">
              • Disk kullanımını göster
            </div>
            <div style="padding: 8px; background: var(--bg); border-radius: 4px; cursor: pointer;" onclick="document.getElementById('aiPrompt').value = 'Sistem bilgilerini göster'">
              • Sistem bilgilerini göster
            </div>
            <div style="padding: 8px; background: var(--bg); border-radius: 4px; cursor: pointer;" onclick="document.getElementById('aiPrompt').value = 'Memory ayarlarını göster'">
              • Memory ayarlarını göster
            </div>
          </div>
        </div>
        
        <div style="display: flex; gap: 10px; justify-content: flex-end;">
          <button onclick="closeAIAssistant()" style="padding: 10px 20px; background: var(--muted); color: white; border: none; border-radius: 4px; cursor: pointer;">
            İptal
          </button>
          <button onclick="generateSQL()" style="padding: 10px 20px; background: var(--brand); color: white; border: none; border-radius: 4px; cursor: pointer;">
            🚀 SQL Oluştur
          </button>
        </div>
      </div>
    </div>
    
    {{ theme_script|safe }}
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
  </body>
</html>
"""

# Envanter sayfası
TEMPLATE_ENVANTER = r"""
<!doctype html>
<html lang="tr">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Envanter - PostgreSQL Management System</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
      :root {
        --bg: #0f1216; --panel: #171b21; --muted: #9aa5b1; --txt: #eef2f6; --brand: #50b0ff; --accent: #7cf; --ring: rgba(80,176,255,.35);
        --drop: #0f1216; --hover: #212833;
      }
      
      /* Light mode variables */
      [data-theme="light"] {
        --bg: #f8fafc; --panel: #ffffff; --muted: #64748b; --txt: #1e293b; --brand: #3b82f6; --accent: #06b6d4; --ring: rgba(59,130,246,.35);
        --drop: #ffffff; --hover: #f1f5f9;
      }
      
      /* Dark mode variables */
      [data-theme="dark"] {
        --bg: #0f1216; --panel: #171b21; --muted: #9aa5b1; --txt: #eef2f6; --brand: #50b0ff; --accent: #7cf; --ring: rgba(80,176,255,.35);
        --drop: #0f1216; --hover: #212833;
      }
      
      body { 
        padding-top: 20px; 
        background: var(--bg); 
        color: var(--txt);
        font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif;
      }
      
      [data-theme="dark"] body { background: linear-gradient(180deg, #0c0f13, #0f1216); }
      [data-theme="light"] body { background: linear-gradient(180deg, #f1f5f9, #f8fafc); }
      
      .container-lg { background: var(--panel); border-radius: 1rem; padding: 2rem; margin-top: 1rem; border: 1px solid; }
      [data-theme="dark"] .container-lg { border-color: #242b37; }
      [data-theme="light"] .container-lg { border-color: #e2e8f0; }
      
      .card { background: var(--panel); border: 1px solid; border-radius: 1rem; padding: 2rem; margin-bottom: 2rem; }
      [data-theme="dark"] .card { border-color: #243044; }
      [data-theme="light"] .card { border-color: #e2e8f0; }
      
      .btn-primary { background: var(--brand); border-color: var(--brand); }
      .btn-primary:hover { background: var(--accent); border-color: var(--accent); }
      .btn-success { background: #10b981; border-color: #10b981; }
      .btn-info { background: #3b82f6; border-color: #3b82f6; }
      .btn-warning { background: #f59e0b; border-color: #f59e0b; }
      
      .btn { padding: 1rem 2rem; font-size: 1.1rem; font-weight: 600; border-radius: 0.75rem; text-decoration: none; display: inline-flex; align-items: center; justify-content: center; gap: 0.75rem; transition: all 0.3s ease; box-shadow: 0 4px 12px rgba(0,0,0,0.15); }
      .btn:hover { transform: translateY(-2px); box-shadow: 0 8px 24px rgba(0,0,0,0.25); }
      
      .btn-icon { font-size: 1.5rem; }
      
      .card-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 2rem; margin-top: 2rem; }
      
      .card h3 { color: var(--brand); margin-bottom: 1rem; font-size: 1.5rem; }
      .card p { color: var(--muted); margin-bottom: 1.5rem; line-height: 1.6; }
      
      .header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 2rem; }
      .header h1 { margin: 0; color: var(--txt); }
      
      /* Theme Toggle Button */
      #themeToggle { all: unset; cursor: pointer; padding: 0.5rem; border-radius: 0.5rem; display: flex; align-items: center; justify-content: center; background: var(--hover); border: 1px solid transparent; }
      #themeToggle:hover { background: var(--hover); border-color: var(--brand); }
      [data-theme="dark"] #themeToggle:hover { border-color: #50b0ff; }
      [data-theme="light"] #themeToggle:hover { border-color: #3b82f6; }
    </style>
  </head>
  <body>
    <div class="container-lg">
      <div class="header">
        <h1>📋 Envanter Yönetimi</h1>
        <div style="display: flex; align-items: center; gap: 1rem;">
          <a href="/" class="btn btn-outline-secondary" style="padding: 0.5rem 1rem; font-size: 0.9rem;">← Ana Sayfa</a>
          <button id="themeToggle" title="Dark/Light Mode Toggle">
            <span id="themeIcon" style="font-size: 1.2rem;">🌙</span>
          </button>
        </div>
      </div>
      
      <div class="card">
        <h3>Sunucu Envanteri</h3>
        <p>PostgreSQL sunucularınızı yönetmek için aşağıdaki seçeneklerden birini kullanabilirsiniz.</p>
        
        <div class="card-grid">
          <div class="card">
            <h3>📊 Sunucuları Listele</h3>
            <p>Mevcut kayıtlı PostgreSQL sunucularınızı görüntüleyin, düzenleyin veya silin.</p>
            <a href="/sunuculari-listele" class="btn btn-info">
              <span class="btn-icon">📋</span>
              Sunucuları Listele
            </a>
          </div>
          
          <div class="card">
            <h3>➕ Manuel Sunucu Ekle</h3>
            <p>Tek bir PostgreSQL sunucusunu manuel olarak ekleyin. Sunucu bilgilerini tek tek girebilirsiniz.</p>
            <a href="/manuel-sunucu-ekle" class="btn btn-primary">
              <span class="btn-icon">➕</span>
              Manuel Sunucu Ekle
            </a>
          </div>
          
          <div class="card">
            <h3>📦 Toplu Sunucu Ekle</h3>
            <p>Excel dosyasından sunucu isimlerini alıp SSH ile otomatik bilgi toplama.</p>
            <a href="/toplu-sunucu-ekle" class="btn btn-warning">
              <span class="btn-icon">📦</span>
              Toplu Sunucu Ekle
            </a>
          </div>
        </div>
      </div>
    </div>
    
    {{ theme_script|safe }}
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
  </body>
</html>
"""

# Manuel sunucu ekleme form sayfası
TEMPLATE_MANUEL_SUNUCU_EKLE = r"""
<!doctype html>
<html lang="tr">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Manuel Sunucu Ekle - PostgreSQL Management System</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
      :root {
        --bg: #0f1216; --panel: #171b21; --muted: #9aa5b1; --txt: #eef2f6; --brand: #50b0ff; --accent: #7cf; --ring: rgba(80,176,255,.35);
        --drop: #0f1216; --hover: #212833;
      }
      
      /* Light mode variables */
      [data-theme="light"] {
        --bg: #f8fafc; --panel: #ffffff; --muted: #64748b; --txt: #1e293b; --brand: #3b82f6; --accent: #06b6d4; --ring: rgba(59,130,246,.35);
        --drop: #ffffff; --hover: #f1f5f9;
      }
      
      /* Dark mode variables */
      [data-theme="dark"] {
        --bg: #0f1216; --panel: #171b21; --muted: #9aa5b1; --txt: #eef2f6; --brand: #50b0ff; --accent: #7cf; --ring: rgba(80,176,255,.35);
        --drop: #0f1216; --hover: #212833;
      }
      
      body { 
        padding-top: 20px; 
        background: var(--bg); 
        color: var(--txt);
        font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif;
      }
      
      [data-theme="dark"] body { background: linear-gradient(180deg, #0c0f13, #0f1216); }
      [data-theme="light"] body { background: linear-gradient(180deg, #f1f5f9, #f8fafc); }
      
      .container-lg { background: var(--panel); border-radius: 1rem; padding: 2rem; margin-top: 1rem; border: 1px solid; max-width: 800px; }
      [data-theme="dark"] .container-lg { border-color: #242b37; }
      [data-theme="light"] .container-lg { border-color: #e2e8f0; }
      
      .card { background: var(--panel); border: 1px solid; border-radius: 1rem; padding: 2rem; margin-bottom: 2rem; }
      [data-theme="dark"] .card { border-color: #243044; }
      [data-theme="light"] .card { border-color: #e2e8f0; }
      
      .form-control, .form-select { background: var(--panel); color: var(--txt); border: 1px solid; }
      [data-theme="dark"] .form-control, .form-select { border-color: #243044; }
      [data-theme="light"] .form-control, .form-select { border-color: #e2e8f0; }
      
      .form-control:focus, .form-select:focus { background: var(--panel); color: var(--txt); border-color: var(--brand); box-shadow: 0 0 0 0.2rem var(--ring); }
      
      .btn-primary { background: var(--brand); border-color: var(--brand); }
      .btn-primary:hover { background: var(--accent); border-color: var(--accent); }
      .btn-outline-secondary { color: var(--muted); border-color: var(--muted); }
      .btn-outline-secondary:hover { background: var(--muted); border-color: var(--muted); }
      
      .alert { border: 1px solid; }
      .alert-success { background: rgba(16, 185, 129, 0.1); border-color: #10b981; color: #10b981; }
      .alert-danger { background: rgba(239, 68, 68, 0.1); border-color: #ef4444; color: #ef4444; }
      
      .header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 2rem; }
      .header h1 { margin: 0; color: var(--txt); }
      
      .form-label { font-weight: 600; margin-bottom: 0.5rem; }
      
      /* Theme Toggle Button */
      #themeToggle { all: unset; cursor: pointer; padding: 0.5rem; border-radius: 0.5rem; display: flex; align-items: center; justify-content: center; background: var(--hover); border: 1px solid transparent; }
      #themeToggle:hover { background: var(--hover); border-color: var(--brand); }
      [data-theme="dark"] #themeToggle:hover { border-color: #50b0ff; }
      [data-theme="light"] #themeToggle:hover { border-color: #3b82f6; }
      
      .loading { display: none; }
      .spinner-border-sm { width: 1rem; height: 1rem; }
    </style>
  </head>
  <body>
    <div class="container-lg">
      <div class="header">
        <h1>🖥️ Manuel Sunucu Ekle</h1>
        <div style="display: flex; align-items: center; gap: 1rem;">
          <a href="/envanter" class="btn btn-outline-secondary" style="padding: 0.5rem 1rem; font-size: 0.9rem;">← Envanter</a>
          <button id="themeToggle" title="Dark/Light Mode Toggle">
            <span id="themeIcon" style="font-size: 1.2rem;">🌙</span>
          </button>
        </div>
      </div>
      
      {% with messages = get_flashed_messages(with_categories=true) %}
        {% if messages %}
          {% for category, message in messages %}
            <div class="alert alert-{{ category }}">
              {{ message }}
            </div>
          {% endfor %}
        {% endif %}
      {% endwith %}
      
      <div class="card">
        <h3>SSH Bağlantı Bilgileri</h3>
        <p class="text-muted">Sunucuya SSH ile bağlanarak sistem bilgilerini otomatik olarak toplayacağız.</p>
        
        <form method="POST" id="serverForm">
          <div class="row">
            <div class="col-md-6">
              <div class="mb-3">
                <label for="hostname" class="form-label">Sunucu Hostname</label>
                <input type="text" class="form-control" id="hostname" name="hostname" required placeholder="örn: web-server-01">
              </div>
            </div>
            <div class="col-md-6">
              <div class="mb-3">
                <label for="ip" class="form-label">Sunucu IP Adresi</label>
                <input type="text" class="form-control" id="ip" name="ip" required placeholder="örn: 192.168.1.100">
              </div>
            </div>
          </div>
          
          <div class="row">
            <div class="col-md-4">
              <div class="mb-3">
                <label for="ssh_port" class="form-label">SSH Port</label>
                <input type="number" class="form-control" id="ssh_port" name="ssh_port" value="22" min="1" max="65535">
              </div>
            </div>
            <div class="col-md-8">
              <div class="mb-3">
                <label for="ssh_user" class="form-label">SSH Kullanıcı</label>
                <input type="text" class="form-control" id="ssh_user" name="ssh_user" required placeholder="örn: root, ubuntu, centos">
              </div>
            </div>
          </div>
          
          <div class="mb-3">
            <label for="password" class="form-label">SSH Şifre</label>
            <input type="password" class="form-control" id="password" name="password" required placeholder="SSH kullanıcı şifresi">
          </div>
          
          <div class="d-grid gap-2 d-md-flex justify-content-md-end">
            <a href="/envanter" class="btn btn-outline-secondary me-md-2">İptal</a>
            <button type="submit" class="btn btn-primary">
              <span class="loading spinner-border spinner-border-sm me-2" role="status"></span>
              <span class="btn-text">Sunucu Bilgilerini Topla</span>
            </button>
          </div>
        </form>
      </div>
      
      <div class="card">
        <h4>📋 Toplanacak Bilgiler</h4>
        <div class="row">
          <div class="col-md-6">
            <ul class="text-muted">
              <li>Sunucu Hostname</li>
              <li>Sunucu IP Adresi</li>
              <li>İşletim Sistemi</li>
              <li>CPU Bilgisi</li>
              <li>CPU Core Sayısı</li>
              <li>Toplam RAM</li>
              <li>Disk Bilgileri</li>
            </ul>
          </div>
          <div class="col-md-6">
            <ul class="text-muted">
              <li>Sistem Uptime</li>
              <li>PostgreSQL Durumu</li>
              <li>PostgreSQL Versiyonu</li>
              <li>Replication Durumu</li>
              <li>pgBackRest Durumu</li>
            </ul>
          </div>
        </div>
      </div>
    </div>
    
    <script>
      // Form submit loading
      document.getElementById('serverForm').addEventListener('submit', function() {
        const submitBtn = this.querySelector('button[type="submit"]');
        const loading = submitBtn.querySelector('.loading');
        const btnText = submitBtn.querySelector('.btn-text');
        
        loading.style.display = 'inline-block';
        btnText.textContent = 'Bağlanıyor...';
        submitBtn.disabled = true;
      });
    </script>
    
    {{ theme_script|safe }}
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
  </body>
</html>
"""

# Toplu sunucu ekleme sayfası
TEMPLATE_TOPLU_SUNUCU_EKLE = r"""
<!doctype html>
<html lang="tr">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Toplu Sunucu Ekle - PostgreSQL Management System</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
      :root {
        --bg: #0f1216; --panel: #171b21; --muted: #9aa5b1; --txt: #eef2f6; --brand: #50b0ff; --accent: #7cf; --ring: rgba(80,176,255,.35);
        --drop: #0f1216; --hover: #212833;
      }
      
      /* Light mode variables */
      [data-theme="light"] {
        --bg: #f8fafc; --panel: #ffffff; --muted: #64748b; --txt: #1e293b; --brand: #3b82f6; --accent: #06b6d4; --ring: rgba(59,130,246,.35);
        --drop: #ffffff; --hover: #f1f5f9;
      }
      
      /* Dark mode variables */
      [data-theme="dark"] {
        --bg: #0f1216; --panel: #171b21; --muted: #9aa5b1; --txt: #eef2f6; --brand: #50b0ff; --accent: #7cf; --ring: rgba(80,176,255,.35);
        --drop: #0f1216; --hover: #212833;
      }
      
      body { 
        padding-top: 20px; 
        background: var(--bg); 
        color: var(--txt);
        font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif;
      }
      
      [data-theme="dark"] body { background: linear-gradient(180deg, #0c0f13, #0f1216); }
      [data-theme="light"] body { background: linear-gradient(180deg, #f1f5f9, #f8fafc); }
      
      .container-lg { background: var(--panel); border-radius: 1rem; padding: 2rem; margin-top: 1rem; border: 1px solid; }
      [data-theme="dark"] .container-lg { border-color: #242b37; }
      [data-theme="light"] .container-lg { border-color: #e2e8f0; }
      
      .card { background: var(--panel); border: 1px solid; }
      [data-theme="dark"] .card { border-color: #243044; }
      [data-theme="light"] .card { border-color: #e2e8f0; }
      
      .form-control, .form-select { background: var(--panel); color: var(--txt); border: 1px solid; }
      [data-theme="dark"] .form-control, .form-select { border-color: #243044; }
      [data-theme="light"] .form-control, .form-select { border-color: #e2e8f0; }
      
      .form-control:focus, .form-select:focus { background: var(--panel); color: var(--txt); border-color: var(--brand); box-shadow: 0 0 0 0.2rem var(--ring); }
      
      .btn-primary { background: var(--brand); border-color: var(--brand); }
      .btn-primary:hover { background: var(--accent); border-color: var(--accent); }
      .btn-warning { background: #f59e0b; border-color: #f59e0b; }
      
      .btn { padding: 1rem 2rem; font-size: 1.1rem; font-weight: 600; border-radius: 0.75rem; text-decoration: none; display: inline-flex; align-items: center; justify-content: center; gap: 0.75rem; transition: all 0.3s ease; box-shadow: 0 4px 12px rgba(0,0,0,0.15); }
      .btn:hover { transform: translateY(-2px); box-shadow: 0 8px 24px rgba(0,0,0,0.25); }
      
      .btn-icon { font-size: 1.5rem; }
      
      .header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 2rem; }
      .header h1 { margin: 0; color: var(--txt); }
      
      /* Theme Toggle Button */
      #themeToggle { all: unset; cursor: pointer; padding: 0.5rem; border-radius: 0.5rem; display: flex; align-items: center; justify-content: center; background: var(--hover); border: 1px solid transparent; }
      #themeToggle:hover { background: var(--hover); border-color: var(--brand); }
      [data-theme="dark"] #themeToggle:hover { border-color: #50b0ff; }
      [data-theme="light"] #themeToggle:hover { border-color: #3b82f6; }
      
      /* Progress bar */
      .progress { height: 1.5rem; background: var(--hover); border-radius: 0.75rem; overflow: hidden; }
      .progress-bar { background: linear-gradient(90deg, var(--brand), var(--accent)); transition: width 0.3s ease; }
      
      /* Results table */
      .results-table { margin-top: 2rem; }
      .table { color: var(--txt); background: var(--panel); }
      .table-striped > tbody > tr:nth-of-type(odd) > td { background: var(--hover); }
      
      .status-success { background: rgba(16, 185, 129, 0.1); color: #10b981; border: 1px solid rgba(16, 185, 129, 0.2); padding: 0.25rem 0.5rem; border-radius: 0.25rem; font-weight: 600; }
      .status-danger { background: rgba(239, 68, 68, 0.1); color: #ef4444; border: 1px solid rgba(239, 68, 68, 0.2); padding: 0.25rem 0.5rem; border-radius: 0.25rem; font-weight: 600; }
      .status-warning { background: rgba(245, 158, 11, 0.1); color: #f59e0b; border: 1px solid rgba(245, 158, 11, 0.2); padding: 0.25rem 0.5rem; border-radius: 0.25rem; font-weight: 600; }
    </style>
  </head>
  <body>
    <div class="container-lg">
      <div class="header">
        <h1>📦 Toplu Sunucu Ekle</h1>
        <div style="display: flex; align-items: center; gap: 1rem;">
          <a href="/envanter" class="btn btn-outline-secondary" style="padding: 0.5rem 1rem; font-size: 0.9rem;">← Envanter</a>
          <button id="themeToggle" title="Dark/Light Mode Toggle">
            <span id="themeIcon" style="font-size: 1.2rem;">🌙</span>
          </button>
        </div>
      </div>
      
      {% with messages = get_flashed_messages(with_categories=true) %}
        {% if messages %}
          {% for category, message in messages %}
            <div class="alert alert-{{ category }}">
              {{ message }}
            </div>
          {% endfor %}
        {% endif %}
      {% endwith %}
      
      <div class="card">
        <h3>Excel Dosyası ve SSH Bilgileri</h3>
        <p class="text-muted">Excel dosyasından sunucu isimlerini alıp SSH ile otomatik bilgi toplama yapacağız.</p>
        
        <form method="POST" enctype="multipart/form-data" id="bulkForm">
          <div class="row">
            <div class="col-md-6">
              <div class="mb-3">
                <label for="excel_file" class="form-label">Excel Dosyası</label>
                <input type="file" class="form-control" id="excel_file" name="excel_file" accept=".xlsx,.xls" required>
                <div class="form-text">Excel dosyasında sunucu isimleri ilk sütunda olmalıdır.</div>
              </div>
            </div>
            <div class="col-md-6">
              <div class="mb-3">
                <label for="ssh_user" class="form-label">SSH Kullanıcı</label>
                <input type="text" class="form-control" id="ssh_user" name="ssh_user" required placeholder="örn: root, ubuntu, centos">
              </div>
            </div>
          </div>
          
          <div class="row">
            <div class="col-md-6">
              <div class="mb-3">
                <label for="ssh_password" class="form-label">SSH Şifre</label>
                <input type="password" class="form-control" id="ssh_password" name="ssh_password" required placeholder="SSH kullanıcı şifresi">
              </div>
            </div>
            <div class="col-md-6">
              <div class="mb-3">
                <label for="ssh_port" class="form-label">SSH Port</label>
                <input type="number" class="form-control" id="ssh_port" name="ssh_port" value="22" min="1" max="65535">
              </div>
            </div>
          </div>
          
          <div class="d-grid gap-2 d-md-flex justify-content-md-end">
            <a href="/envanter" class="btn btn-outline-secondary me-md-2">İptal</a>
            <button type="submit" class="btn btn-warning">
              <span class="loading spinner-border spinner-border-sm me-2" role="status" style="display: none;"></span>
              <span class="btn-text">Toplu Tarama Başlat</span>
            </button>
          </div>
        </form>
      </div>
      
      <div class="card">
        <h4>📋 Toplanacak Bilgiler</h4>
        <div class="row">
          <div class="col-md-6">
            <ul class="text-muted">
              <li>Sunucu Hostname</li>
              <li>Sunucu IP Adresi</li>
              <li>İşletim Sistemi</li>
              <li>CPU Bilgisi</li>
              <li>CPU Core Sayısı</li>
              <li>Toplam RAM</li>
              <li>Disk Bilgileri</li>
            </ul>
          </div>
          <div class="col-md-6">
            <ul class="text-muted">
              <li>Sistem Uptime</li>
              <li>PostgreSQL Durumu</li>
              <li>PostgreSQL Versiyonu</li>
              <li>Replication Durumu</li>
              <li>pgBackRest Durumu</li>
            </ul>
          </div>
        </div>
      </div>
      
      {% if results %}
      <div class="results-table">
        <div class="card">
          <h4>📊 Toplu Tarama Sonuçları</h4>
          <div class="table-responsive">
            <table class="table table-striped">
              <thead>
                <tr>
                  <th>Hostname</th>
                  <th>IP</th>
                  <th>OS</th>
                  <th>CPU</th>
                  <th>RAM</th>
                  <th>Disk</th>
                  <th>Uptime</th>
                  <th>PostgreSQL</th>
                  <th>Versiyon</th>
                  <th>Replication</th>
                  <th>pgBackRest</th>
                </tr>
              </thead>
              <tbody>
                {% for result in results %}
                <tr>
                  <td><strong>{{ result.hostname }}</strong></td>
                  <td>{{ result.ip }}</td>
                  <td>{{ result.os_info }}</td>
                  <td>{{ result.cpu_info }}</td>
                  <td>{{ result.ram_total }}</td>
                  <td>
                    {% if result.disks is string %}
                      {{ result.disks }}
                    {% elif result.disks %}
                      {% for disk in result.disks %}
                        <div style="font-size: 0.8rem; margin-bottom: 0.25rem;">
                          {{ disk.device }}: {{ disk.percent }}
                          {% if disk.percent_num >= 80 %}
                            <span class="status-danger">⚠️</span>
                          {% endif %}
                        </div>
                      {% endfor %}
                    {% endif %}
                  </td>
                  <td>{{ result.uptime }}</td>
                  <td>
                    {% if result.postgresql_status == 'Var' %}
                      <span class="status-success">✓ Var</span>
                    {% else %}
                      <span class="status-danger">✗ Yok</span>
                    {% endif %}
                  </td>
                  <td>{{ result.postgresql_version if result.postgresql_status == 'Var' else 'N/A' }}</td>
                  <td>
                    {% if result.postgresql_status == 'Var' %}
                      {% if result.postgresql_replication == 'Var' %}
                        <span class="status-success">✓ Var</span>
                      {% else %}
                        <span class="status-danger">✗ Yok</span>
                      {% endif %}
                    {% else %}
                      N/A
                    {% endif %}
                  </td>
                  <td>
                    {% if result.pgbackrest_status == 'Var' %}
                      <span class="status-success">✓ Var</span>
                    {% else %}
                      <span class="status-danger">✗ Yok</span>
                    {% endif %}
                  </td>
                </tr>
                {% endfor %}
              </tbody>
            </table>
          </div>
          
          <div class="d-grid gap-2 d-md-flex justify-content-md-end mt-4">
            <button class="btn btn-success me-md-2" onclick="addAllToInventory()">📋 Tümünü Envantere Ekle</button>
            <button class="btn btn-primary" onclick="exportToExcel()">📊 Excel'e Aktar</button>
          </div>
        </div>
      </div>
      {% endif %}
    </div>
    
    <script>
      // Form submit loading
      document.getElementById('bulkForm').addEventListener('submit', function() {
        const submitBtn = this.querySelector('button[type="submit"]');
        const loading = submitBtn.querySelector('.loading');
        const btnText = submitBtn.querySelector('.btn-text');
        
        loading.style.display = 'inline-block';
        btnText.textContent = 'Tarama Başlatılıyor...';
        submitBtn.disabled = true;
      });
      
      function exportToExcel() {
        alert('Excel export özelliği geliştirme aşamasındadır!');
      }
      
      function addAllToInventory() {
        if (confirm('Tüm sunucuları envantere eklemek istediğinizden emin misiniz?')) {
          const results = [
            {% if results %}
              {% for result in results %}
                {
                  hostname: '{{ result.hostname }}',
                  ip: '{{ result.ip }}',
                  ssh_port: '{{ result.ssh_port }}',
                  ssh_user: '{{ result.ssh_user }}',
                  ssh_password: '{{ result.ssh_password }}',
                  os_info: '{{ result.os_info }}',
                  cpu_info: '{{ result.cpu_info }}',
                  cpu_cores: '{{ result.cpu_cores }}',
                  ram_total: '{{ result.ram_total }}',
                  disks: {{ result.disks|tojson }},
                  uptime: '{{ result.uptime }}',
                  postgresql_status: '{{ result.postgresql_status }}',
                  postgresql_version: '{{ result.postgresql_version }}',
                  postgresql_replication: '{{ result.postgresql_replication }}',
                  pgbackrest_status: '{{ result.pgbackrest_status }}'
                }{% if not loop.last %},{% endif %}
              {% endfor %}
            {% endif %}
          ];
          
          console.log('Toplam sunucu sayısı:', results.length);
          let completed = 0;
          let errors = 0;
          
          // Her sunucuyu sırayla ekle
          results.forEach((serverData, index) => {
            setTimeout(() => {
              addSingleToInventoryAsync(serverData, index + 1, results.length)
                .then(() => {
                  completed++;
                  console.log(`Sunucu ${index + 1}/${results.length} eklendi: ${serverData.hostname}`);
                  
                  if (completed + errors === results.length) {
                    alert(`İşlem tamamlandı! ${completed} sunucu eklendi, ${errors} hata.`);
                    window.location.href = '/sunuculari-listele';
                  }
                })
                .catch((error) => {
                  errors++;
                  console.error(`Sunucu ${index + 1} eklenemedi: ${serverData.hostname}`, error);
                  
                  if (completed + errors === results.length) {
                    alert(`İşlem tamamlandı! ${completed} sunucu eklendi, ${errors} hata.`);
                    window.location.href = '/sunuculari-listele';
                  }
                });
            }, index * 500); // Her sunucu arasında 500ms bekle
          });
        }
      }
      
      function addSingleToInventory(serverData) {
        const form = document.createElement('form');
        form.method = 'POST';
        form.action = '/envantere-ekle';
        form.style.display = 'none';
        
        for (const [key, value] of Object.entries(serverData)) {
          const input = document.createElement('input');
          input.type = 'hidden';
          input.name = key;
          input.value = value;
          form.appendChild(input);
        }
        
        document.body.appendChild(form);
        form.submit();
        document.body.removeChild(form);
      }
      
      function addSingleToInventoryAsync(serverData, current, total) {
        return new Promise((resolve, reject) => {
          const formData = new FormData();
          
          for (const [key, value] of Object.entries(serverData)) {
            formData.append(key, value);
          }
          
          fetch('/envantere-ekle', {
            method: 'POST',
            body: formData
          })
          .then(response => {
            if (response.ok) {
              resolve(response);
            } else {
              reject(new Error(`HTTP ${response.status}: ${response.statusText}`));
            }
          })
          .catch(error => {
            reject(error);
          });
        });
      }
    </script>
    
    {{ theme_script|safe }}
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
  </body>
</html>
"""

# Sunucu bilgileri görüntüleme sayfası
TEMPLATE_SUNUCU_BILGILERI = r"""
<!doctype html>
<html lang="tr">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Sunucu Bilgileri - PostgreSQL Management System</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
      :root {
        --bg: #0f1216; --panel: #171b21; --muted: #9aa5b1; --txt: #eef2f6; --brand: #50b0ff; --accent: #7cf; --ring: rgba(80,176,255,.35);
        --drop: #0f1216; --hover: #212833;
      }
      
      /* Light mode variables */
      [data-theme="light"] {
        --bg: #f8fafc; --panel: #ffffff; --muted: #64748b; --txt: #1e293b; --brand: #3b82f6; --accent: #06b6d4; --ring: rgba(59,130,246,.35);
        --drop: #ffffff; --hover: #f1f5f9;
      }
      
      /* Dark mode variables */
      [data-theme="dark"] {
        --bg: #0f1216; --panel: #171b21; --muted: #9aa5b1; --txt: #eef2f6; --brand: #50b0ff; --accent: #7cf; --ring: rgba(80,176,255,.35);
        --drop: #0f1216; --hover: #212833;
      }
      
      body { 
        padding-top: 20px; 
        background: var(--bg); 
        color: var(--txt);
        font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif;
      }
      
      [data-theme="dark"] body { background: linear-gradient(180deg, #0c0f13, #0f1216); }
      [data-theme="light"] body { background: linear-gradient(180deg, #f1f5f9, #f8fafc); }
      
      .container-lg { background: var(--panel); border-radius: 1rem; padding: 2rem; margin-top: 1rem; border: 1px solid; }
      [data-theme="dark"] .container-lg { border-color: #242b37; }
      [data-theme="light"] .container-lg { border-color: #e2e8f0; }
      
      .table { color: var(--txt); background: var(--panel); }
      .table-striped > tbody > tr:nth-of-type(odd) > td { background: var(--hover); }
      .table th { background: var(--brand); color: white; border: none; font-weight: 600; }
      .table td { border: 1px solid; padding: 0.75rem; }
      [data-theme="dark"] .table td { border-color: #243044; }
      [data-theme="light"] .table td { border-color: #e2e8f0; }
      
      .btn-primary { background: var(--brand); border-color: var(--brand); }
      .btn-primary:hover { background: var(--accent); border-color: var(--accent); }
      .btn-outline-secondary { color: var(--muted); border-color: var(--muted); }
      .btn-outline-secondary:hover { background: var(--muted); border-color: var(--muted); }
      
      .header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 2rem; }
      .header h1 { margin: 0; color: var(--txt); }
      
      .info-card { background: var(--panel); border: 1px solid; border-radius: 1rem; padding: 1.5rem; margin-bottom: 2rem; }
      [data-theme="dark"] .info-card { border-color: #243044; }
      [data-theme="light"] .info-card { border-color: #e2e8f0; }
      
      .status-badge {
        padding: 0.25rem 0.75rem;
        border-radius: 1rem;
        font-size: 0.875rem;
        font-weight: 600;
      }
      
      .status-success {
        background: rgba(16, 185, 129, 0.1);
        color: #10b981;
        border: 1px solid rgba(16, 185, 129, 0.2);
      }
      
      .status-danger {
        background: rgba(239, 68, 68, 0.1);
        color: #ef4444;
        border: 1px solid rgba(239, 68, 68, 0.2);
      }
      
      /* Disk bilgileri stilleri */
      .disk-list {
        display: flex;
        flex-direction: column;
        gap: 0.75rem;
      }
      
      .disk-item {
        background: var(--hover);
        border: 1px solid;
        border-radius: 0.5rem;
        padding: 0.75rem;
        border-color: #243044;
      }
      
      [data-theme="light"] .disk-item {
        border-color: #e2e8f0;
      }
      
      .disk-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 0.5rem;
      }
      
      .disk-mount {
        color: var(--muted);
        font-size: 0.875rem;
        font-style: italic;
      }
      
      .disk-details {
        font-size: 0.875rem;
        color: var(--txt);
      }
      
      .disk-size, .disk-used, .disk-available {
        font-weight: 500;
      }
      
      .disk-percent {
        font-weight: 600;
        margin-left: 0.5rem;
        padding: 0.25rem 0.5rem;
        border-radius: 0.25rem;
        background: rgba(16, 185, 129, 0.1);
        color: #10b981;
        border: 1px solid rgba(16, 185, 129, 0.2);
      }
      
      .disk-warning {
        background: rgba(239, 68, 68, 0.1) !important;
        color: #ef4444 !important;
        border: 1px solid rgba(239, 68, 68, 0.2) !important;
        animation: pulse-warning 2s infinite;
      }
      
      @keyframes pulse-warning {
        0%, 100% { opacity: 1; }
        50% { opacity: 0.7; }
      }
      
      /* Theme Toggle Button */
      #themeToggle { all: unset; cursor: pointer; padding: 0.5rem; border-radius: 0.5rem; display: flex; align-items: center; justify-content: center; background: var(--hover); border: 1px solid transparent; }
      #themeToggle:hover { background: var(--hover); border-color: var(--brand); }
      [data-theme="dark"] #themeToggle:hover { border-color: #50b0ff; }
      [data-theme="light"] #themeToggle:hover { border-color: #3b82f6; }
    </style>
  </head>
  <body>
    <div class="container-lg">
      <div class="header">
        <h1>📊 Sunucu Bilgileri</h1>
        <div style="display: flex; align-items: center; gap: 1rem;">
          <a href="/manuel-sunucu-ekle" class="btn btn-outline-secondary" style="padding: 0.5rem 1rem; font-size: 0.9rem;">← Yeni Tarama</a>
          <button id="themeToggle" title="Dark/Light Mode Toggle">
            <span id="themeIcon" style="font-size: 1.2rem;">🌙</span>
          </button>
        </div>
      </div>
      
      <div class="info-card">
        <h4>🖥️ {{ server_info.hostname }}</h4>
        <p class="text-muted mb-0">IP: {{ server_info.ip }} | SSH Port: {{ server_info.ssh_port }} | Kullanıcı: {{ server_info.ssh_user }}</p>
      </div>
      
      <div class="table-responsive">
        <table class="table table-striped">
          <thead>
            <tr>
              <th style="width: 30%;">Özellik</th>
              <th style="width: 70%;">Değer</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td><strong>Sunucu Hostname</strong></td>
              <td>{{ server_info.hostname }}</td>
            </tr>
            <tr>
              <td><strong>Sunucu IP Adresi</strong></td>
              <td>{{ server_info.ip }}</td>
            </tr>
            <tr>
              <td><strong>İşletim Sistemi</strong></td>
              <td>{{ server_info.os_info }}</td>
            </tr>
            <tr>
              <td><strong>CPU Bilgisi</strong></td>
              <td>{{ server_info.cpu_info }}</td>
            </tr>
            <tr>
              <td><strong>CPU Core Sayısı</strong></td>
              <td>{{ server_info.cpu_cores }}</td>
            </tr>
            <tr>
              <td><strong>Toplam RAM</strong></td>
              <td>{{ server_info.ram_total }}</td>
            </tr>
            <tr>
              <td><strong>Disk Bilgileri</strong></td>
              <td>
                {% if server_info.disks is string %}
                  {{ server_info.disks }}
                {% elif server_info.disks %}
                  <div class="disk-list">
                    {% for disk in server_info.disks %}
                      <div class="disk-item">
                        <div class="disk-header">
                          <strong>{{ disk.device }}</strong>
                          <span class="disk-mount">{{ disk.mount }}</span>
                        </div>
                        <div class="disk-details">
                          <span class="disk-size">{{ disk.size }}</span> toplam | 
                          <span class="disk-used">{{ disk.used }}</span> kullanılan | 
                          <span class="disk-available">{{ disk.available }}</span> boş
                          <span class="disk-percent {% if disk.percent_num >= 80 %}disk-warning{% endif %}">
                            ({{ disk.percent }})
                          </span>
                        </div>
                      </div>
                    {% endfor %}
                  </div>
                {% else %}
                  Disk bilgisi alınamadı
                {% endif %}
              </td>
            </tr>
            <tr>
              <td><strong>Sistem Uptime</strong></td>
              <td>{{ server_info.uptime }}</td>
            </tr>
            <tr>
              <td><strong>PostgreSQL Durumu</strong></td>
              <td>
                {% if server_info.postgresql_status == 'Var' %}
                  <span class="status-badge status-success">✓ Var</span>
                {% else %}
                  <span class="status-badge status-danger">✗ Yok</span>
                {% endif %}
              </td>
            </tr>
            {% if server_info.postgresql_status == 'Var' %}
            <tr>
              <td><strong>PostgreSQL Versiyonu</strong></td>
              <td>{{ server_info.postgresql_version }}</td>
            </tr>
            <tr>
              <td><strong>PostgreSQL Replication</strong></td>
              <td>
                {% if server_info.postgresql_replication == 'Var' %}
                  <span class="status-badge status-success">✓ Var</span>
                {% else %}
                  <span class="status-badge status-danger">✗ Yok</span>
                {% endif %}
              </td>
            </tr>
            {% endif %}
            <tr>
              <td><strong>pgBackRest Durumu</strong></td>
              <td>
                {% if server_info.pgbackrest_status == 'Var' %}
                  <span class="status-badge status-success">✓ Var</span>
                {% else %}
                  <span class="status-badge status-danger">✗ Yok</span>
                {% endif %}
              </td>
            </tr>
          </tbody>
        </table>
      </div>
      
      <div class="d-grid gap-2 d-md-flex justify-content-md-end mt-4">
        <a href="/envanter" class="btn btn-outline-secondary me-md-2">Envanter'e Dön</a>
        <button class="btn btn-success me-md-2" onclick="addToInventory()">📋 Envantere Ekle</button>
        <button class="btn btn-primary" onclick="exportToExcel()">📊 Excel'e Aktar</button>
      </div>
    </div>
    
    <script>
      function exportToExcel() {
        // Excel export functionality
        alert('Excel export özelliği geliştirme aşamasındadır!');
      }
      
      function addToInventory() {
        // Sunucu bilgilerini form olarak gönder
        const form = document.createElement('form');
        form.method = 'POST';
        form.action = '/envantere-ekle';
        
        // Tüm sunucu bilgilerini form alanları olarak ekle
        const serverData = {
          hostname: '{{ server_info.hostname }}',
          ip: '{{ server_info.ip }}',
          ssh_port: '{{ server_info.ssh_port }}',
          ssh_user: '{{ server_info.ssh_user }}',
          ssh_password: '{{ server_info.ssh_password }}',
          os_info: '{{ server_info.os_info }}',
          cpu_info: '{{ server_info.cpu_info }}',
          cpu_cores: '{{ server_info.cpu_cores }}',
          ram_total: '{{ server_info.ram_total }}',
          disks: '{{ server_info.disks|tojson }}',
          uptime: '{{ server_info.uptime }}',
          postgresql_status: '{{ server_info.postgresql_status }}',
          postgresql_version: '{{ server_info.postgresql_version }}',
          postgresql_replication: '{{ server_info.postgresql_replication }}',
          pgbackrest_status: '{{ server_info.pgbackrest_status }}'
        };
        
        for (const [key, value] of Object.entries(serverData)) {
          const input = document.createElement('input');
          input.type = 'hidden';
          input.name = key;
          input.value = value;
          form.appendChild(input);
        }
        
        document.body.appendChild(form);
        form.submit();
      }
    </script>
    
    {{ theme_script|safe }}
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
  </body>
</html>
"""

# Healthcheck sayfası
TEMPLATE_HEALTHCHECK = r"""
<!doctype html>
<html lang="tr">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Healthcheck</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
      :root {
        --bg: #0f1216; --panel: #171b21; --muted: #9aa5b1; --txt: #eef2f6; --brand: #50b0ff; --accent: #7cf; --ring: rgba(80,176,255,.35);
        --drop: #0f1216; --hover: #212833; --border: #243044;
      }
      
      [data-theme="light"] {
        --bg: #f8fafc; --panel: #ffffff; --muted: #64748b; --txt: #1e293b; --brand: #3b82f6; --accent: #06b6d4; --ring: rgba(59,130,246,.35);
        --drop: #ffffff; --hover: #f1f5f9; --border: #e2e8f0;
      }
      
      body { 
        background: var(--bg); 
        color: var(--txt); 
        font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif;
        padding-top: 20px;
        min-height: 100vh;
      }
      
      .container-lg { 
        background: var(--panel); 
        border-radius: 1rem; 
        padding: 2rem; 
        margin-top: 1rem; 
        margin-bottom: 2rem;
        border: 1px solid var(--border);
        max-width: 1400px;
      }
      
      .header { 
        display: flex; 
        align-items: center; 
        justify-content: space-between; 
        margin-bottom: 2rem; 
      }
      
      .header h1 { 
        margin: 0; 
        color: var(--txt); 
      }
      
      .card { 
        background: var(--panel); 
        border: 1px solid var(--border); 
        border-radius: 1rem; 
        padding: 1.5rem; 
        margin-bottom: 1.5rem;
        transition: all 0.3s ease;
      }
      
      .card:hover {
        transform: translateY(-2px);
        box-shadow: 0 8px 24px rgba(0,0,0,0.15);
      }
      
      .btn { 
        border-radius: 0.5rem; 
        padding: 0.5rem 1rem; 
        font-weight: 500;
        transition: all 0.2s ease;
      }
      
      .btn-primary { 
        background: var(--brand); 
        border-color: var(--brand); 
        color: white;
      }
      
      .btn-primary:hover:not(:disabled) { 
        background: var(--accent); 
        border-color: var(--accent); 
        transform: translateY(-1px);
        box-shadow: 0 4px 12px rgba(0,0,0,0.15);
      }
      
      .btn-success {
        background: #10b981;
        border-color: #10b981;
        color: white;
      }
      
      .btn-success:hover:not(:disabled) {
        background: #059669;
        border-color: #059669;
      }
      
      .btn-outline-secondary { 
        color: var(--muted); 
        border-color: var(--muted); 
      }
      
      .btn-outline-secondary:hover { 
        background: var(--muted); 
        border-color: var(--muted); 
        color: white;
      }
      
      /* Theme Toggle Button */
      #themeToggle { 
        all: unset; 
        cursor: pointer; 
        padding: 0.5rem; 
        border-radius: 0.5rem; 
        display: flex; 
        align-items: center; 
        justify-content: center; 
        background: var(--hover); 
        border: 1px solid transparent; 
      }
      
      #themeToggle:hover { 
        background: var(--hover); 
        border-color: var(--brand); 
      }
      
      /* Server List Styling */
      .server-list {
        max-height: 400px;
        overflow-y: auto;
        border: 1px solid var(--border);
        border-radius: 0.5rem;
        padding: 1rem;
        background: var(--hover);
      }
      
      .server-item {
        padding: 0.75rem;
        margin-bottom: 0.5rem;
        border: 1px solid var(--border);
        border-radius: 0.5rem;
        background: var(--panel);
        transition: all 0.2s ease;
      }
      
      .server-item:hover {
        background: var(--hover);
        transform: translateX(5px);
      }
      
      .server-item label {
        cursor: pointer;
        display: flex;
        align-items: center;
        margin: 0;
      }
      
      .server-item input[type="checkbox"] {
        margin-right: 0.75rem;
        width: 18px;
        height: 18px;
        cursor: pointer;
      }
      
      /* Results Styling */
      .result-card {
        border-left: 4px solid;
        margin-bottom: 1rem;
        padding: 1.25rem;
        border-radius: 0.5rem;
        background: var(--hover);
      }
      
      .result-card.success {
        border-left-color: #10b981;
      }
      
      .result-card.error {
        border-left-color: #ef4444;
      }
      
      .result-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        margin-bottom: 1rem;
      }
      
      .result-badge {
        padding: 0.25rem 0.75rem;
        border-radius: 0.25rem;
        font-size: 0.875rem;
        font-weight: 500;
      }
      
      .result-badge.success {
        background: rgba(16, 185, 129, 0.2);
        color: #10b981;
      }
      
      .result-badge.error {
        background: rgba(239, 68, 68, 0.2);
        color: #ef4444;
      }
      
      .result-details {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
        gap: 1rem;
        margin-top: 1rem;
      }
      
      .detail-item {
        padding: 0.75rem;
        background: var(--panel);
        border-radius: 0.5rem;
        border: 1px solid var(--border);
      }
      
      .detail-label {
        font-size: 0.875rem;
        color: var(--muted);
        margin-bottom: 0.25rem;
      }
      
      .detail-value {
        font-weight: 500;
        color: var(--txt);
      }
      
      /* Loading Spinner */
      .spinner {
        border: 3px solid var(--border);
        border-top: 3px solid var(--brand);
        border-radius: 50%;
        width: 40px;
        height: 40px;
        animation: spin 1s linear infinite;
        margin: 0 auto;
      }
      
      @keyframes spin {
        0% { transform: rotate(0deg); }
        100% { transform: rotate(360deg); }
      }
      
      .loading-overlay {
        display: none;
        position: fixed;
        top: 0;
        left: 0;
        right: 0;
        bottom: 0;
        background: rgba(0, 0, 0, 0.5);
        z-index: 9999;
        align-items: center;
        justify-content: center;
      }
      
      .loading-content {
        background: var(--panel);
        padding: 2rem;
        border-radius: 1rem;
        text-align: center;
        border: 1px solid var(--border);
      }
      
      /* Scrollbar Styling */
      ::-webkit-scrollbar {
        width: 8px;
        height: 8px;
      }
      
      ::-webkit-scrollbar-track {
        background: var(--panel);
      }
      
      ::-webkit-scrollbar-thumb {
        background: var(--border);
        border-radius: 4px;
      }
      
      ::-webkit-scrollbar-thumb:hover {
        background: var(--brand);
      }
      
      .text-muted { color: var(--muted) !important; }
      p, div, span, td, th, label, h1, h2, h3, h4, h5, h6 { color: var(--txt); }
      
      .table {
        color: var(--txt);
      }
      
      .table th {
        background: var(--hover);
        border-color: var(--border);
      }
      
      .table td {
        border-color: var(--border);
      }
      
      .table-hover tbody tr:hover {
        background: var(--hover);
      }
      
      /* Detail Modal Styling */
      .modal-content {
        background: var(--panel);
        color: var(--txt);
        border: 1px solid var(--border);
      }
      
      .modal-header {
        border-bottom: 1px solid var(--border);
      }
      
      .modal-footer {
        border-top: 1px solid var(--border);
      }
      
      .detail-section {
        margin-bottom: 2rem;
        padding-bottom: 1.5rem;
        border-bottom: 1px solid var(--border);
      }
      
      .detail-section:last-child {
        border-bottom: none;
      }
      
      .detail-section-title {
        color: var(--txt);
        font-size: 1.1rem;
        font-weight: 600;
        margin-bottom: 1rem;
        padding-bottom: 0.5rem;
        border-bottom: 2px solid var(--brand);
      }
      
      .detail-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
        gap: 0.75rem;
      }
      
      .detail-row {
        display: flex;
        justify-content: space-between;
        padding: 0.5rem;
        background: var(--hover);
        border-radius: 0.25rem;
        align-items: center;
      }
      
      .detail-row .detail-label {
        font-weight: 600;
        color: var(--muted);
        font-size: 0.9rem;
      }
      
      .detail-row .detail-value {
        color: var(--txt);
        text-align: right;
        font-weight: 500;
      }
      
      .modal-body {
        max-height: 70vh;
        overflow-y: auto;
      }
      
      .btn-close {
        filter: invert(1);
      }
      
      [data-theme="light"] .btn-close {
        filter: invert(0);
      }
      
      /* Animations */
      @keyframes slideIn {
        from {
          width: 0%;
          opacity: 0.5;
        }
        to {
          width: var(--target-width);
          opacity: 1;
        }
      }
    </style>
  </head>
  <body>
    <div class="loading-overlay" id="loadingOverlay">
      <div class="loading-content">
        <div class="spinner"></div>
        <p class="mt-3 mb-0">Healthcheck çalıştırılıyor...</p>
        <p class="text-muted mb-0" style="font-size: 0.875rem;">Lütfen bekleyin</p>
      </div>
    </div>
    
    <div class="container-lg">
      <div class="header">
        <h1>🏥 Healthcheck</h1>
        <div style="display: flex; align-items: center; gap: 1rem;">
          <button id="themeToggle" title="Dark/Light Mode Toggle">
            <span id="themeIcon" style="font-size: 1.2rem;">🌙</span>
          </button>
          <a href="/" class="btn btn-outline-secondary">← Ana Sayfa</a>
        </div>
      </div>
      
      <div class="row">
        <div class="col-md-12">
          <div class="card">
            <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 1rem;">
              <h3 style="margin: 0;">Sunucu Seçimi</h3>
              <div>
                <button class="btn btn-outline-secondary btn-sm me-2" onclick="selectAllServers()">Tümünü Seç</button>
                <button class="btn btn-outline-secondary btn-sm" onclick="deselectAllServers()">Seçimi Temizle</button>
              </div>
            </div>
            
            <p class="text-muted mb-3">
              Healthcheck yapılacak sunucuları seçin. Seçilen sunucular üzerinde sistem bilgileri toplanacak ve kaydedilecektir.
            </p>
            
            <div class="server-list" id="serverList">
              {% if servers %}
                {% for server in servers %}
                <div class="server-item">
                  <label>
                    <input type="checkbox" name="server_ids" value="{{ server.id }}" class="server-checkbox">
                    <div>
                      <strong>{{ server.hostname }}</strong>
                      <span class="text-muted" style="font-size: 0.875rem;"> - {{ server.ip }}:{{ server.ssh_port }}</span>
                      {% if server.postgresql_status %}
                      <span class="badge bg-success" style="font-size: 0.75rem; margin-left: 0.5rem;">PostgreSQL</span>
                      {% endif %}
                    </div>
                  </label>
                </div>
                {% endfor %}
              {% else %}
                <div class="alert alert-warning" style="background: rgba(245, 158, 11, 0.1); border: 1px solid rgba(245, 158, 11, 0.2); border-radius: 0.5rem; padding: 1rem;">
                  <strong>⚠️ Sunucu Bulunamadı</strong><br>
                  Envanter'de kayıtlı sunucu bulunmamaktadır. Önce sunucu eklemeniz gerekmektedir.
                </div>
              {% endif %}
            </div>
            
            <div class="mt-3">
              <button class="btn btn-success btn-lg" onclick="runHealthcheck()" id="runButton" {% if not servers %}disabled{% endif %}>
                🚀 Healthcheck Çalıştır (<span id="selectedCount">0</span> sunucu)
              </button>
            </div>
          </div>
        </div>
      </div>
      
      <div id="resultsContainer"></div>
      
      <!-- Healthcheck Geçmişi -->
      <div class="row mt-4">
        <div class="col-md-12">
          <div class="card">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem;">
              <div>
                <h3 style="margin: 0;">📊 Healthcheck Geçmişi</h3>
                <p class="text-muted mb-0" style="font-size: 0.9rem; margin-top: 0.25rem;">Son healthcheck sonuçları</p>
              </div>
              {% if history %}
              <div style="display: flex; gap: 0.5rem; align-items: center;">
                <button class="btn btn-outline-secondary btn-sm" onclick="selectAllHistory()">
                  <input type="checkbox" id="selectAllCheckbox" style="margin-right: 0.5rem;">Tümünü Seç
                </button>
                <button class="btn btn-danger btn-sm" onclick="deleteSelectedHistory()" id="deleteSelectedBtn" disabled>
                  🗑️ Seçilenleri Sil (<span id="selectedHistoryCount">0</span>)
                </button>
              </div>
              {% endif %}
            </div>
            
            <div class="table-responsive">
              <table class="table table-hover">
                <thead>
                  <tr>
                    <th style="width: 40px;"></th>
                    <th>Tarih</th>
                    <th>Sunucu</th>
                    <th>IP</th>
                    <th>Durum</th>
                    <th>CPU</th>
                    <th>RAM</th>
                    <th>PostgreSQL</th>
                    <th>Kontrol Eden</th>
                    <th style="text-align: center;">İşlemler</th>
                  </tr>
                </thead>
                <tbody>
                  {% if history %}
                    {% for record in history %}
                    <tr>
                      <td>
                        <input type="checkbox" class="history-checkbox" value="{{ record.id }}" onchange="updateDeleteButton()">
                      </td>
                      <td style="font-size: 0.875rem;">{{ record.created_at }}</td>
                      <td><strong>{{ record.hostname }}</strong></td>
                      <td class="text-muted">{{ record.ip }}</td>
                      <td>
                        {% if record.status == 'success' %}
                          <span class="result-badge success">✓ Başarılı</span>
                        {% else %}
                          <span class="result-badge error">✗ Hata</span>
                        {% endif %}
                      </td>
                      <td>{{ record.cpu_info or 'N/A' }}</td>
                      <td>{{ record.ram_total or 'N/A' }}</td>
                      <td>
                        {% if record.postgresql_status == 'Var' %}
                          <span class="badge bg-success">Var</span>
                        {% else %}
                          <span class="badge bg-secondary">Yok</span>
                        {% endif %}
                      </td>
                      <td class="text-muted">{{ record.checked_by_username }}</td>
                      <td style="text-align: center;">
                        <a href="/healthcheck/detail/{{ record.id }}" class="btn btn-primary btn-sm" style="margin-right: 0.25rem;">📋 Detay</a>
                        <button onclick="deleteSingleHistory({{ record.id }}, '{{ record.hostname }}')" class="btn btn-danger btn-sm" title="Sil">🗑️</button>
                      </td>
                    </tr>
                    {% endfor %}
                  {% else %}
                    <tr>
                      <td colspan="10" class="text-center text-muted">Henüz healthcheck geçmişi bulunmamaktadır.</td>
                    </tr>
                  {% endif %}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>
    </div>
    
    <!-- Detail Modal -->
    <div class="modal fade" id="detailModal" tabindex="-1" aria-labelledby="detailModalLabel" aria-hidden="true">
      <div class="modal-dialog modal-xl modal-dialog-scrollable">
        <div class="modal-content">
          <div class="modal-header">
            <h5 class="modal-title" id="detailModalTitle">Detaylı Bilgiler</h5>
            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
          </div>
          <div class="modal-body" id="detailModalBody">
            <p class="text-muted">Yükleniyor...</p>
          </div>
          <div class="modal-footer">
            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Kapat</button>
          </div>
        </div>
      </div>
    </div>
    
    <script>
      // Theme management
      function initTheme() {
        const savedTheme = localStorage.getItem('theme') || 'dark';
        document.documentElement.setAttribute('data-theme', savedTheme);
        const themeIcon = document.getElementById('themeIcon');
        if (themeIcon) {
          themeIcon.textContent = savedTheme === 'dark' ? '🌙' : '☀️';
        }
      }

      function toggleTheme() {
        const currentTheme = document.documentElement.getAttribute('data-theme');
        const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
        
        document.documentElement.setAttribute('data-theme', newTheme);
        
        const themeIcon = document.getElementById('themeIcon');
        if (themeIcon) {
          themeIcon.textContent = newTheme === 'dark' ? '🌙' : '☀️';
        }
        
        localStorage.setItem('theme', newTheme);
      }

      // Server selection
      function updateSelectedCount() {
        const checkboxes = document.querySelectorAll('.server-checkbox:checked');
        document.getElementById('selectedCount').textContent = checkboxes.length;
      }

      function selectAllServers() {
        const checkboxes = document.querySelectorAll('.server-checkbox');
        checkboxes.forEach(cb => cb.checked = true);
        updateSelectedCount();
      }

      function deselectAllServers() {
        const checkboxes = document.querySelectorAll('.server-checkbox');
        checkboxes.forEach(cb => cb.checked = false);
        updateSelectedCount();
      }

      // Run healthcheck
      async function runHealthcheck() {
        try {
          const checkboxes = document.querySelectorAll('.server-checkbox:checked');
          
          if (!checkboxes || checkboxes.length === 0) {
            alert('Lütfen en az bir sunucu seçin!');
            return;
          }
          
          const serverIds = Array.from(checkboxes).map(cb => cb.value);
          
          console.log('[DEBUG] Selected server IDs:', serverIds);
          
          if (serverIds.length === 0) {
            alert('Lütfen en az bir sunucu seçin!');
            return;
          }
          
          // Show loading
          document.getElementById('loadingOverlay').style.display = 'flex';
          document.getElementById('runButton').disabled = true;
          
          try {
            const response = await fetch('/api/healthcheck/run', {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
              },
              body: JSON.stringify({ server_ids: serverIds })
            });
            
            console.log('[DEBUG] Response status:', response.status);
            
            if (!response.ok) {
              throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            
            const data = await response.json();
            
            console.log('[DEBUG] Response data:', data);
            
            // Display results
            displayResults(data);
            
            // Reload page to show updated history after user has time to review
            // setTimeout(() => {
            //   window.location.reload();
            // }, 10000);
            
          } catch (error) {
            console.error('[ERROR] Healthcheck fetch error:', error);
            alert('Healthcheck sırasında hata oluştu: ' + error.message);
          } finally {
            document.getElementById('loadingOverlay').style.display = 'none';
            document.getElementById('runButton').disabled = false;
          }
        } catch (error) {
          console.error('[ERROR] runHealthcheck exception:', error);
          alert('Healthcheck başlatılamadı: ' + error.message);
          document.getElementById('loadingOverlay').style.display = 'none';
          document.getElementById('runButton').disabled = false;
        }
      }

      // Global variable to store detailed results
      let detailedResults = [];

      function displayResults(data) {
        try {
          console.log('[DEBUG] displayResults called with data:', data);
          
          // Güvenlik kontrolleri
          if (!data) {
            throw new Error('Veri alınamadı (data is null/undefined)');
          }
          
          if (!data.results) {
            throw new Error('Sonuç listesi bulunamadı (data.results is undefined)');
          }
          
          if (!Array.isArray(data.results)) {
            throw new Error('Sonuç listesi geçersiz format (data.results is not an array)');
          }
          
          const container = document.getElementById('resultsContainer');
          detailedResults = data.results;
          
          let html = '<div class="row mt-4"><div class="col-md-12"><div class="card">';
          html += '<h3>✅ Healthcheck Sonuçları</h3>';
          html += `<p class="text-muted mb-3">${data.results.length} sunucu kontrol edildi</p>`;
        
        data.results.forEach((result, index) => {
          const statusClass = result.status === 'success' ? 'success' : 'error';
          const statusBadge = result.status === 'success' ? '✓ Başarılı' : '✗ Hata';
          
          html += `<div class="result-card ${statusClass}">`;
          html += `<div class="result-header">`;
          html += `<div><h4 style="margin: 0;">${result.hostname}</h4><span class="text-muted">${result.ip}</span></div>`;
          html += `<div style="display: flex; gap: 0.5rem; align-items: center;">`;
          html += `<span class="result-badge ${statusClass}">${statusBadge}</span>`;
          if (result.status === 'success') {
            html += `<button class="btn btn-primary btn-sm" onclick="showDetails(${index})">📋 Detay Gör</button>`;
          }
          html += `</div>`;
          html += `</div>`;
          
          if (result.status === 'success') {
            html += '<div class="result-details">';
            
            if (result.os_info) {
              html += `<div class="detail-item"><div class="detail-label">İşletim Sistemi</div><div class="detail-value">${result.os_info}</div></div>`;
            }
            
            if (result.cpu_info) {
              html += `<div class="detail-item"><div class="detail-label">CPU</div><div class="detail-value">${result.cpu_info}</div></div>`;
            }
            
            if (result.cpu_details && result.cpu_details !== 'N/A') {
              html += `<div class="detail-item"><div class="detail-label">CPU Detayları</div><div class="detail-value" style="font-size: 0.9rem; color: var(--txt-secondary);">${result.cpu_details}</div></div>`;
            }
            
            if (result.ram_total) {
              html += `<div class="detail-item"><div class="detail-label">RAM</div><div class="detail-value">${result.ram_total}</div></div>`;
            }
            
            if (result.uptime) {
              html += `<div class="detail-item"><div class="detail-label">Uptime</div><div class="detail-value">${result.uptime}</div></div>`;
            }
            
            if (result.postgresql_status) {
              const pgBadge = result.postgresql_status === 'Var' ? 'success' : 'secondary';
              const pgDetailsNA = result.postgresql_status === 'Var' && 
                                  (result.pg_connection_count === 'N/A' || !result.pg_connection_count) && 
                                  (result.pg_databases === 'N/A' || !result.pg_databases);
              const warningIcon = pgDetailsNA ? ' <span title="Detaylı bilgiler alınamadı. Sudo yetkisi gerekiyor." style="cursor: help;">⚠️</span>' : '';
              html += `<div class="detail-item"><div class="detail-label">PostgreSQL</div><div class="detail-value"><span class="badge bg-${pgBadge}">${result.postgresql_status}</span> ${result.postgresql_version || ''}${warningIcon}</div></div>`;
            }
            
            if (result.load_average) {
              html += `<div class="detail-item"><div class="detail-label">Load Average</div><div class="detail-value">${result.load_average}</div></div>`;
            }
            
            html += '</div>';
          } else {
            html += `<div class="alert alert-danger mt-2" style="background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.2);">`;
            html += `<strong>Hata:</strong> ${result.error_message || 'Bilinmeyen hata'}`;
            html += `</div>`;
          }
          
          html += '</div>';
        });
        
          html += '</div></div></div>';
          container.innerHTML = html;
          
          // Scroll to results
          container.scrollIntoView({ behavior: 'smooth', block: 'start' });
          
        } catch (error) {
          console.error('[ERROR] displayResults exception:', error);
          alert('Sonuçlar gösterilirken hata oluştu: ' + error.message + '\\n\\nDetay için F12 > Console');
        }
      }

      function showDetails(index) {
        try {
          const result = detailedResults[index];
          
          // Güvenlik kontrolü
          if (!result) {
            alert('Sonuç bulunamadı!');
            return;
          }
          
          const modalBody = document.getElementById('detailModalBody');
          const modalTitle = document.getElementById('detailModalTitle');
          
          modalTitle.textContent = `${result.hostname || 'Bilinmeyen Sunucu'} - Detaylı Bilgiler`;
          
          let html = '';
          
          console.log('[DEBUG] showDetails called for:', result.hostname, 'Result object:', result);
        
        // Sistem Bilgileri
        html += '<div class="detail-section">';
        html += '<h5 class="detail-section-title">🖥️ Sistem Bilgileri</h5>';
        html += '<div class="detail-grid">';
        html += `<div class="detail-row"><span class="detail-label">İşletim Sistemi:</span><span class="detail-value">${result.os_info || 'N/A'}</span></div>`;
        html += `<div class="detail-row"><span class="detail-label">Kernel Versiyon:</span><span class="detail-value">${result.kernel_version || 'N/A'}</span></div>`;
        html += `<div class="detail-row"><span class="detail-label">Mimari:</span><span class="detail-value">${result.architecture || 'N/A'}</span></div>`;
        html += `<div class="detail-row"><span class="detail-label">Hostname:</span><span class="detail-value">${result.hostname}</span></div>`;
        html += `<div class="detail-row"><span class="detail-label">IP Adresi:</span><span class="detail-value">${result.ip}</span></div>`;
        html += `<div class="detail-row"><span class="detail-label">Uptime:</span><span class="detail-value">${result.uptime || 'N/A'}</span></div>`;
        html += `<div class="detail-row"><span class="detail-label">Son Başlatma:</span><span class="detail-value">${result.last_boot || 'N/A'}</span></div>`;
        html += `<div class="detail-row"><span class="detail-label">Timezone:</span><span class="detail-value">${result.timezone || 'N/A'}</span></div>`;
        html += '</div>';
        
        // System Update Status - Güzel gösterim
        if (result.system_update_status && result.system_update_status !== 'N/A') {
          html += '<div style="margin-top: 1rem;">';
          let updateBgColor, updateBorderColor, updateTextColor, updateIcon;
          
          if (result.system_update_status === 'up-to-date') {
            updateBgColor = 'rgba(16, 185, 129, 0.1)';
            updateBorderColor = 'rgba(16, 185, 129, 0.3)';
            updateTextColor = '#10b981';
            updateIcon = '✓';
          } else if (result.system_update_status === 'updates-available') {
            updateBgColor = 'rgba(245, 158, 11, 0.1)';
            updateBorderColor = 'rgba(245, 158, 11, 0.3)';
            updateTextColor = '#f59e0b';
            updateIcon = '⚠️';
          } else {
            updateBgColor = 'rgba(107, 114, 128, 0.1)';
            updateBorderColor = 'rgba(107, 114, 128, 0.3)';
            updateTextColor = '#6b7280';
            updateIcon = 'ℹ️';
          }
          
          html += `<div style="background: ${updateBgColor}; border: 1px solid ${updateBorderColor}; border-radius: 0.5rem; padding: 0.75rem;">`;
          html += `<div style="display: flex; align-items: center; gap: 0.5rem;">`;
          html += `<span style="font-size: 1.2rem;">${updateIcon}</span>`;
          html += `<div style="flex: 1;">`;
          html += `<div style="font-weight: 600; color: ${updateTextColor}; font-size: 0.9rem;">Sistem Güncellemeleri</div>`;
          html += `<div style="font-size: 0.85rem; color: var(--txt); margin-top: 0.25rem;">${result.system_update_message || 'Durum bilinmiyor'}</div>`;
          html += `</div></div></div>`;
          html += '</div>';
        }
        
        html += '</div>';
        
        // CPU Bilgileri
        html += '<div class="detail-section">';
        html += '<h5 class="detail-section-title">⚙️ CPU Bilgileri</h5>';
        html += '<div class="detail-grid">';
        html += `<div class="detail-row"><span class="detail-label">CPU:</span><span class="detail-value">${result.cpu_info || 'N/A'}</span></div>`;
        if (result.cpu_details && result.cpu_details !== 'N/A') {
          html += `<div class="detail-row"><span class="detail-label">Detaylar:</span><span class="detail-value" style="font-size: 0.9rem; color: var(--txt-secondary);">${result.cpu_details}</span></div>`;
        }
        html += `<div class="detail-row"><span class="detail-label">Load Average:</span><span class="detail-value">${result.load_average || 'N/A'}</span></div>`;
        html += '</div>';
        
        // Top CPU Processes - Alt alta güzel gösterim
        if (result.top_cpu_processes && result.top_cpu_processes !== 'N/A' && typeof result.top_cpu_processes === 'string') {
          html += '<div style="margin-top: 1rem;">';
          html += '<h6 style="color: var(--txt); font-size: 0.95rem; margin-bottom: 0.75rem;">📊 En Çok CPU Kullanan İşlemler</h6>';
          const cpuProcesses = result.top_cpu_processes.split(' | ');
          cpuProcesses.forEach((proc, idx) => {
            const parts = proc.trim().split(/\s+/);
            const percentage = parts[parts.length - 1];
            const processName = parts.slice(0, -1).join(' ');
            const percentNum = parseFloat(percentage);
            const barColor = percentNum > 50 ? '#ef4444' : percentNum > 20 ? '#f59e0b' : '#10b981';
            
            html += `<div style="background: var(--hover); padding: 0.75rem; border-radius: 0.5rem; margin-bottom: 0.5rem; border-left: 3px solid ${barColor};">`;
            html += `<div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.25rem;">`;
            html += `<span style="font-size: 0.85rem; font-family: monospace; color: var(--txt);">${processName}</span>`;
            html += `<span style="font-weight: 600; color: ${barColor}; font-size: 0.9rem;">${percentage}</span>`;
            html += `</div>`;
            html += `<div style="background: var(--panel); height: 6px; border-radius: 3px; overflow: hidden;">`;
            html += `<div style="background: ${barColor}; height: 100%; width: ${Math.min(percentNum * 2, 100)}%; transition: width 0.3s;"></div>`;
            html += `</div></div>`;
          });
          html += '</div>';
        }
        html += '</div>';
        
        // RAM Bilgileri
        html += '<div class="detail-section">';
        html += '<h5 class="detail-section-title">💾 RAM Bilgileri</h5>';
        html += '<div class="detail-grid">';
        html += `<div class="detail-row"><span class="detail-label">Total RAM:</span><span class="detail-value">${result.ram_total || 'N/A'}</span></div>`;
        html += `<div class="detail-row"><span class="detail-label">Kullanılan:</span><span class="detail-value">${result.ram_used || 'N/A'}</span></div>`;
        html += `<div class="detail-row"><span class="detail-label">Boş:</span><span class="detail-value">${result.ram_free || 'N/A'}</span></div>`;
        html += `<div class="detail-row"><span class="detail-label">Detaylı:</span><span class="detail-value">${result.memory_detailed || 'N/A'}</span></div>`;
        html += `<div class="detail-row" style="grid-column: 1 / -1;"><span class="detail-label">Swap Memory:</span><span class="detail-value">${result.swap_memory || 'N/A'}</span></div>`;
        html += '</div>';
        
        // Top Memory Processes - Alt alta güzel gösterim
        if (result.top_memory_processes && result.top_memory_processes !== 'N/A' && typeof result.top_memory_processes === 'string') {
          html += '<div style="margin-top: 1rem;">';
          html += '<h6 style="color: var(--txt); font-size: 0.95rem; margin-bottom: 0.75rem;">📊 En Çok RAM Kullanan İşlemler</h6>';
          const memProcesses = result.top_memory_processes.split(' | ');
          memProcesses.forEach((proc, idx) => {
            const parts = proc.trim().split(/\s+/);
            const percentage = parts[parts.length - 1];
            const processName = parts.slice(0, -1).join(' ');
            const percentNum = parseFloat(percentage);
            const barColor = percentNum > 50 ? '#ef4444' : percentNum > 20 ? '#f59e0b' : '#10b981';
            
            html += `<div style="background: var(--hover); padding: 0.75rem; border-radius: 0.5rem; margin-bottom: 0.5rem; border-left: 3px solid ${barColor};">`;
            html += `<div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.25rem;">`;
            html += `<span style="font-size: 0.85rem; font-family: monospace; color: var(--txt);">${processName}</span>`;
            html += `<span style="font-weight: 600; color: ${barColor}; font-size: 0.9rem;">${percentage}</span>`;
            html += `</div>`;
            html += `<div style="background: var(--panel); height: 6px; border-radius: 3px; overflow: hidden;">`;
            html += `<div style="background: ${barColor}; height: 100%; width: ${Math.min(percentNum * 2, 100)}%; transition: width 0.3s;"></div>`;
            html += `</div></div>`;
          });
          html += '</div>';
        }
        html += '</div>';
        
        // Disk Bilgileri
        html += '<div class="detail-section">';
        html += '<h5 class="detail-section-title">💿 Disk Bilgileri</h5>';
        if (result.disks && result.disks !== '[]' && result.disks !== 'N/A') {
          try {
            const disks = typeof result.disks === 'string' ? JSON.parse(result.disks) : result.disks;
            if (Array.isArray(disks) && disks.length > 0) {
              html += '<div class="table-responsive"><table class="table table-sm table-hover" style="font-size: 0.85rem;"><thead><tr><th>Device</th><th>Size</th><th>Used</th><th>Avail</th><th>Use%</th><th>Mount</th></tr></thead><tbody>';
              disks.forEach(disk => {
                const percentNum = parseInt(disk.percent.replace('%', ''));
                const percentColor = percentNum > 90 ? '#ef4444' : percentNum > 75 ? '#f59e0b' : '#10b981';
                html += `<tr><td>${disk.device}</td><td>${disk.size}</td><td>${disk.used}</td><td>${disk.avail}</td><td><span style="color: ${percentColor}; font-weight: 600;">${disk.percent}</span></td><td>${disk.mount}</td></tr>`;
              });
              html += '</tbody></table></div>';
            } else {
              html += '<p class="text-muted">Disk bilgisi bulunamadı</p>';
            }
          } catch (e) {
            console.error('Disk parsing error:', e);
            html += '<p class="text-muted">Disk bilgisi görüntülenemiyor</p>';
          }
        } else {
          html += '<p class="text-muted">Disk bilgisi bulunamadı</p>';
        }
        if (result.disk_io_stats && result.disk_io_stats !== 'N/A') {
          html += `<div class="mt-2"><strong>I/O İstatistikleri:</strong><pre style="font-size: 0.75rem; background: var(--hover); padding: 0.5rem; border-radius: 0.25rem;">${result.disk_io_stats}</pre></div>`;
        }
        
        // Disk Performance Test - Her zaman göster
        html += '<div style="margin-top: 1rem;">';
        html += '<h6 style="color: var(--txt); font-size: 0.95rem; margin-bottom: 0.75rem;">⚡ Disk Performans Testi</h6>';
        
        // Eğer veri varsa göster
        if (result.disk_type && result.disk_type !== 'N/A' && result.disk_type !== undefined) {
          // Disk Type Badge
          const diskTypeColor = result.disk_type === 'SSD' ? '#10b981' : '#f59e0b';
          const diskTypeIcon = result.disk_type === 'SSD' ? '⚡' : '💿';
          html += `<div style="background: var(--hover); border-radius: 0.5rem; padding: 1rem; border-left: 3px solid ${diskTypeColor};">`;
          html += `<div style="display: flex; align-items: center; gap: 0.75rem; margin-bottom: 1rem;">`;
          html += `<span style="font-size: 1.5rem;">${diskTypeIcon}</span>`;
          html += `<div>`;
          html += `<div style="font-weight: 600; color: ${diskTypeColor}; font-size: 1.1rem;">Disk Tipi: ${result.disk_type}</div>`;
          html += `<div style="font-size: 0.75rem; color: var(--muted);">Ana sistem diski</div>`;
          html += `</div></div>`;
          
          // Write Speed
          html += `<div style="margin-bottom: 0.75rem;">`;
          html += `<div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.25rem;">`;
          html += `<span style="font-size: 0.85rem; color: var(--txt);">📝 Yazma Hızı</span>`;
          html += `<span style="font-weight: 600; color: #3b82f6; font-size: 0.95rem;">${result.disk_write_speed || 'N/A'}</span>`;
          html += `</div>`;
          html += `<div style="background: var(--panel); height: 8px; border-radius: 4px; overflow: hidden;">`;
          html += `<div style="background: linear-gradient(90deg, #3b82f6, #06b6d4); height: 100%; width: 70%; animation: slideIn 0.5s ease-out;"></div>`;
          html += `</div></div>`;
          
          // Read Speed
          html += `<div>`;
          html += `<div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.25rem;">`;
          html += `<span style="font-size: 0.85rem; color: var(--txt);">📖 Okuma Hızı</span>`;
          html += `<span style="font-weight: 600; color: #10b981; font-size: 0.95rem;">${result.disk_read_speed || 'N/A'}</span>`;
          html += `</div>`;
          html += `<div style="background: var(--panel); height: 8px; border-radius: 4px; overflow: hidden;">`;
          html += `<div style="background: linear-gradient(90deg, #10b981, #059669); height: 100%; width: 80%; animation: slideIn 0.5s ease-out;"></div>`;
          html += `</div></div>`;
          
          html += '</div>';
        } else {
          // Veri yoksa bilgi mesajı göster
          html += '<div style="background: rgba(107, 114, 128, 0.1); border: 1px solid rgba(107, 114, 128, 0.2); border-radius: 0.5rem; padding: 0.75rem; font-size: 0.85rem; color: var(--muted);">';
          html += 'ℹ️ Disk performans testi bu kayıtta yapılmamış. Yeni bir healthcheck çalıştırarak disk performansını görebilirsiniz.';
          html += '</div>';
        }
        html += '</div>';
        
        html += '</div>';
        
        // Network Bilgileri
        html += '<div class="detail-section">';
        html += '<h5 class="detail-section-title">🌐 Network Bilgileri</h5>';
        html += '<div class="detail-grid">';
        html += `<div class="detail-row"><span class="detail-label">IP Adresleri:</span><span class="detail-value">${result.network_info || 'N/A'}</span></div>`;
        html += `<div class="detail-row"><span class="detail-label">DNS Servers:</span><span class="detail-value">${result.dns_servers || 'N/A'}</span></div>`;
        html += `<div class="detail-row"><span class="detail-label">Toplam Bağlantı:</span><span class="detail-value">${result.total_connections || 'N/A'}</span></div>`;
        html += '</div>';
        
        // Network Interfaces - daha güzel gösterim
        if (result.network_interfaces && result.network_interfaces !== 'N/A' && typeof result.network_interfaces === 'string') {
          html += '<div style="margin-top: 1rem;">';
          html += '<h6 style="color: var(--txt); font-size: 0.95rem; margin-bottom: 0.75rem;">🔌 Network Interfaces</h6>';
          const interfaces = result.network_interfaces.split('\\n');
          interfaces.forEach(iface => {
            if (iface && iface.trim()) {
              html += `<div style="background: var(--hover); padding: 0.5rem 0.75rem; border-radius: 0.5rem; margin-bottom: 0.5rem; font-family: monospace; font-size: 0.85rem; border-left: 3px solid #3b82f6;">${iface.trim()}</div>`;
            }
          });
          html += '</div>';
        }
        
        // Listening Ports - badge formatında
        if (result.listening_ports && result.listening_ports !== 'N/A' && typeof result.listening_ports === 'string') {
          html += '<div style="margin-top: 1rem;">';
          html += '<h6 style="color: var(--txt); font-size: 0.95rem; margin-bottom: 0.75rem;">🔓 Dinlenen Portlar</h6>';
          html += '<div style="display: flex; flex-wrap: wrap; gap: 0.5rem;">';
          const ports = result.listening_ports.split(',').map(p => p.trim());
          ports.forEach(port => {
            if (port && port.length > 0) {
              const portNum = parseInt(port);
              let portColor = '#3b82f6';
              let portLabel = '';
              // Yaygın portları renklendir
              if (portNum === 22) { portColor = '#10b981'; portLabel = ' SSH'; }
              else if (portNum === 80) { portColor = '#f59e0b'; portLabel = ' HTTP'; }
              else if (portNum === 443) { portColor = '#f59e0b'; portLabel = ' HTTPS'; }
              else if (portNum === 5432) { portColor = '#3b82f6'; portLabel = ' PostgreSQL'; }
              else if (portNum === 3306) { portColor = '#ef4444'; portLabel = ' MySQL'; }
              
              html += `<span style="background: ${portColor}; color: white; padding: 0.25rem 0.75rem; border-radius: 0.5rem; font-size: 0.85rem; font-weight: 500;">${port}${portLabel}</span>`;
            }
          });
          html += '</div></div>';
        }
        
        html += '</div>';
        
        // Servisler
        html += '<div class="detail-section">';
        html += '<h5 class="detail-section-title">⚡ Sistem Servisleri</h5>';
        
        // Running Services - badge formatında
        if (result.running_services && result.running_services !== 'N/A' && typeof result.running_services === 'string') {
          html += '<div style="margin-bottom: 1.5rem;">';
          html += '<h6 style="color: var(--txt); font-size: 0.95rem; margin-bottom: 0.75rem;">✅ Çalışan Servisler</h6>';
          html += '<div style="display: flex; flex-wrap: wrap; gap: 0.5rem;">';
          const services = result.running_services.split(',').map(s => s.trim());
          services.forEach(service => {
            if (service && service.length > 0) {
              html += `<span style="background: rgba(16, 185, 129, 0.2); color: #10b981; border: 1px solid rgba(16, 185, 129, 0.3); padding: 0.25rem 0.75rem; border-radius: 0.5rem; font-size: 0.85rem; font-weight: 500; font-family: monospace;">${service}</span>`;
            }
          });
          html += '</div></div>';
        }
        
        // Failed Services - Detaylı gösterim
        html += '<div>';
        html += '<h6 style="color: var(--txt); font-size: 0.95rem; margin-bottom: 0.75rem;">❌ Hatalı Servisler</h6>';
        if (result.failed_services === 'None' || !result.failed_services || result.failed_services === 'N/A') {
          html += '<div style="background: rgba(16, 185, 129, 0.1); border: 1px solid rgba(16, 185, 129, 0.2); border-radius: 0.5rem; padding: 0.75rem; color: #10b981; font-weight: 500;">';
          html += '✓ Hiçbir servis hatası yok';
          html += '</div>';
        } else if (typeof result.failed_services === 'string') {
          // Failed services'ı |||  ile ayırdık (yeni format), eski format virgülle ayrılmış olabilir
          const separator = result.failed_services.includes('|||') ? '|||' : ',';
          const failedServices = result.failed_services.split(separator).map(s => s.trim());
          
          failedServices.forEach(service => {
            if (service && service !== '....' && service.length > 0) {
              // Servis adı ve detayı ayır (parantez içindeki)
              const match = service.match(/^([^\(]+)(\((.+)\))?$/);
              const serviceName = match ? match[1].trim() : service;
              const serviceDetail = match && match[3] ? match[3].trim() : '';
              
              html += '<div style="background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.3); border-left: 4px solid #ef4444; border-radius: 0.5rem; padding: 0.75rem; margin-bottom: 0.5rem;">';
              html += '<div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 0.25rem;">';
              html += `<div style="flex: 1;"><span style="font-weight: 600; color: #ef4444; font-family: monospace; font-size: 0.95rem;">${serviceName}</span>`;
              if (serviceDetail) {
                html += `<div style="font-size: 0.8rem; color: var(--muted); margin-top: 0.25rem; line-height: 1.4; font-family: monospace;">${serviceDetail}</div>`;
              }
              html += '</div>';
              html += '<span style="background: rgba(239, 68, 68, 0.2); color: #ef4444; padding: 0.25rem 0.5rem; border-radius: 0.25rem; font-size: 0.75rem; font-weight: 600;">FAILED</span>';
              html += '</div>';
              html += '</div>';
            }
          });
        }
        html += '</div>';
        
        html += '</div>';
        
        // Kernel Parameters (PostgreSQL için önemli)
        if (result.kernel_params && result.kernel_params !== '{}' && result.kernel_params !== 'N/A') {
          html += '<div class="detail-section">';
          html += '<h5 class="detail-section-title">⚙️ Kernel Parametreleri (PostgreSQL için Kritik)</h5>';
          
          try {
            const kernelParams = typeof result.kernel_params === 'string' ? JSON.parse(result.kernel_params) : result.kernel_params;
            
            // Shared Memory Section
            html += '<h6 style="color: var(--txt); font-size: 0.95rem; margin-bottom: 0.75rem; margin-top: 1rem;">💾 Paylaşımlı Bellek (Shared Memory)</h6>';
            html += '<div class="detail-grid">';
            html += `<div class="detail-row"><span class="detail-label">SHMMAX:</span><span class="detail-value">${kernelParams.shmmax || 'N/A'}</span></div>`;
            html += `<div class="detail-row"><span class="detail-label">SHMALL:</span><span class="detail-value">${kernelParams.shmall || 'N/A'}</span></div>`;
            html += `<div class="detail-row"><span class="detail-label">SHMMNI:</span><span class="detail-value">${kernelParams.shmmni || 'N/A'}</span></div>`;
            html += '</div>';
            
            // Semaphore Section
            html += '<h6 style="color: var(--txt); font-size: 0.95rem; margin-bottom: 0.75rem; margin-top: 1rem;">🔗 Semaphore Parametreleri</h6>';
            html += '<div class="detail-grid">';
            if (kernelParams.semmsl) {
              html += `<div class="detail-row"><span class="detail-label">SEMMSL:</span><span class="detail-value">${kernelParams.semmsl}</span></div>`;
            }
            if (kernelParams.semmns) {
              html += `<div class="detail-row"><span class="detail-label">SEMMNS:</span><span class="detail-value">${kernelParams.semmns}</span></div>`;
            }
            if (kernelParams.semopm) {
              html += `<div class="detail-row"><span class="detail-label">SEMOPM:</span><span class="detail-value">${kernelParams.semopm}</span></div>`;
            }
            if (kernelParams.semmni) {
              html += `<div class="detail-row"><span class="detail-label">SEMMNI:</span><span class="detail-value">${kernelParams.semmni}</span></div>`;
            }
            if (kernelParams.sem) {
              html += `<div class="detail-row" style="grid-column: 1 / -1;"><span class="detail-label">SEM:</span><span class="detail-value">${kernelParams.sem}</span></div>`;
            }
            html += '</div>';
            
            // VM/Memory Tuning Section
            html += '<h6 style="color: var(--txt); font-size: 0.95rem; margin-bottom: 0.75rem; margin-top: 1rem;">📊 VM ve Bellek Ayarları</h6>';
            html += '<div class="detail-grid">';
            
            // Swappiness with color coding
            if (kernelParams.vmswappiness) {
              let swapColor = 'var(--txt)';
              if (kernelParams.vmswappiness.includes('Yüksek')) swapColor = '#ef4444';
              else if (kernelParams.vmswappiness.includes('Düşük')) swapColor = '#10b981';
              html += `<div class="detail-row"><span class="detail-label">VM Swappiness:</span><span class="detail-value" style="color: ${swapColor}; font-weight: 600;">${kernelParams.vmswappiness}</span></div>`;
            }
            
            // THP with color coding
            if (kernelParams.transparent_hugepage) {
              let thpColor = 'var(--txt)';
              if (kernelParams.transparent_hugepage.includes('never')) thpColor = '#10b981';
              else if (kernelParams.transparent_hugepage.includes('always')) thpColor = '#ef4444';
              else if (kernelParams.transparent_hugepage.includes('madvise')) thpColor = '#f59e0b';
              html += `<div class="detail-row"><span class="detail-label">Transparent Huge Pages:</span><span class="detail-value" style="color: ${thpColor}; font-weight: 600;">${kernelParams.transparent_hugepage}</span></div>`;
            }
            
            html += `<div class="detail-row"><span class="detail-label">Dirty Background Ratio:</span><span class="detail-value">${kernelParams.vmdirty_background_ratio || 'N/A'}</span></div>`;
            html += `<div class="detail-row"><span class="detail-label">Dirty Ratio:</span><span class="detail-value">${kernelParams.vmdirty_ratio || 'N/A'}</span></div>`;
            html += `<div class="detail-row"><span class="detail-label">Dirty Background Bytes:</span><span class="detail-value">${kernelParams.vmdirty_background_bytes || 'N/A'}</span></div>`;
            html += `<div class="detail-row"><span class="detail-label">Dirty Bytes:</span><span class="detail-value">${kernelParams.vmdirty_bytes || 'N/A'}</span></div>`;
            html += `<div class="detail-row"><span class="detail-label">Overcommit Memory:</span><span class="detail-value">${kernelParams.vm_overcommit_memory || 'N/A'}</span></div>`;
            html += `<div class="detail-row"><span class="detail-label">Overcommit Ratio:</span><span class="detail-value">${kernelParams.vm_overcommit_ratio || 'N/A'}</span></div>`;
            html += '</div>';
            
            // CPU/Scheduler Section
            html += '<h6 style="color: var(--txt); font-size: 0.95rem; margin-bottom: 0.75rem; margin-top: 1rem;">⚡ CPU ve Scheduler</h6>';
            html += '<div class="detail-grid">';
            html += `<div class="detail-row"><span class="detail-label">Scheduler Autogroup:</span><span class="detail-value">${kernelParams.kernelsched_autogroup_enabled || 'N/A'}</span></div>`;
            html += `<div class="detail-row" style="grid-column: 1 / -1;"><span class="detail-label">CPU Scaling Governor:</span><span class="detail-value">${kernelParams.scaling_governor || 'N/A'}</span></div>`;
            html += '</div>';
            
            html += '</div>';
          } catch (e) {
            console.error('Kernel params parsing error:', e);
            html += '<p class="text-muted">Kernel parametreleri görüntülenemiyor</p></div>';
          }
        }
        
        // PostgreSQL Bilgileri
        if (result.postgresql_status === 'Var') {
          html += '<div class="detail-section">';
          html += '<h5 class="detail-section-title">🐘 PostgreSQL Bilgileri</h5>';
          
          // Check if most PostgreSQL details are N/A (indicating permission issues)
          const pgDetailsNA = (result.pg_connection_count === 'N/A' || !result.pg_connection_count) && 
                              (result.pg_databases === 'N/A' || !result.pg_databases) && 
                              (result.pg_data_directory === 'N/A' || !result.pg_data_directory);
          
          if (pgDetailsNA) {
            html += '<div style="background: rgba(59, 130, 246, 0.1); border: 1px solid rgba(59, 130, 246, 0.3); border-radius: 0.5rem; padding: 1rem; margin-bottom: 1rem;">';
            html += '<div style="display: flex; align-items: start; gap: 0.75rem;">';
            html += '<span style="font-size: 1.5rem;">ℹ️</span>';
            html += '<div>';
            html += '<strong style="color: #3b82f6; font-size: 1rem;">PostgreSQL Detaylı Bilgileri Kısmi Olarak Alındı</strong>';
            html += '<p style="margin: 0.5rem 0 0 0; font-size: 0.9rem; line-height: 1.5; color: var(--txt);">';
            html += 'Sistem <strong>SSH şifrenizi kullanarak sudo</strong> ile bazı bilgileri almayı denedi ancak tüm bilgiler alınamadı. ';
            html += '<strong>Daha detaylı bilgi için</strong> aşağıdaki çözümlerden birini uygulayabilirsiniz:<br><br>';
            html += '<strong>Çözüm 1 - SSH Kullanıcısına Sudo Yetkisi Ver (Önerilen):</strong><br>';
            html += '<code style="display: block; background: var(--hover); padding: 0.75rem; border-radius: 0.25rem; margin-top: 0.5rem; font-size: 0.85rem; overflow-x: auto;">';
            html += '# /etc/sudoers dosyasına ekleyin (visudo komutu ile):<br>';
            html += 'your-ssh-user ALL=(postgres) NOPASSWD: /usr/bin/psql<br><br>';
            html += '# Şifresiz sudo yetkisini test edin:<br>';
            html += 'sudo -n -u postgres psql -c "SELECT version();"';
            html += '</code>';
            html += '<span style="font-size: 0.85rem; color: var(--muted); margin-top: 0.5rem; display: block;"><strong>Not:</strong> <code>your-ssh-user</code> yerine SSH kullanıcınızı yazın (örnek: frk). NOPASSWD eklerseniz her seferinde şifre girmeden çalışır.</span><br>';
            html += '<strong>Çözüm 2 - SSH Kullanıcısı Sudo Grubuna Eklensin:</strong><br>';
            html += '<code style="display: block; background: var(--hover); padding: 0.75rem; border-radius: 0.25rem; margin-top: 0.5rem; font-size: 0.85rem; overflow-x: auto;">';
            html += 'usermod -aG sudo your-ssh-user';
            html += '</code>';
            html += '<span style="font-size: 0.85rem; color: var(--muted); margin-top: 0.5rem; display: block;">Bu durumda sistem SSH şifrenizi sudo şifresi olarak kullanacak.</span>';
            html += '</p>';
            html += '</div></div></div>';
          }
          
          html += '<div class="detail-grid">';
          html += `<div class="detail-row"><span class="detail-label">Durum:</span><span class="detail-value"><span class="badge bg-success">Var</span></span></div>`;
          html += `<div class="detail-row"><span class="detail-label">Versiyon:</span><span class="detail-value">${result.postgresql_version || 'N/A'}</span></div>`;
          html += `<div class="detail-row"><span class="detail-label">Port:</span><span class="detail-value">${result.pg_port || 'N/A'}</span></div>`;
          html += `<div class="detail-row"><span class="detail-label">Data Directory:</span><span class="detail-value">${result.pg_data_directory || 'N/A'}</span></div>`;
          html += `<div class="detail-row"><span class="detail-label">Aktif Bağlantı:</span><span class="detail-value">${result.pg_connection_count || 'N/A'}</span></div>`;
          html += `<div class="detail-row"><span class="detail-label">Max Bağlantı:</span><span class="detail-value">${result.pg_max_connections || 'N/A'}</span></div>`;
          html += `<div class="detail-row"><span class="detail-label">Toplam Boyut:</span><span class="detail-value">${result.pg_total_size || 'N/A'}</span></div>`;
          html += `<div class="detail-row"><span class="detail-label">PostgreSQL Uptime:</span><span class="detail-value">${result.pg_uptime || 'N/A'}</span></div>`;
          html += `<div class="detail-row"><span class="detail-label">Replication:</span><span class="detail-value">${result.postgresql_replication || 'N/A'}</span></div>`;
          html += `<div class="detail-row"><span class="detail-label">pgBackRest:</span><span class="detail-value">${result.pgbackrest_status || 'N/A'}</span></div>`;
          html += '</div>';
          
          // Databases - boyutlarıyla birlikte güzel gösterim
          if (result.pg_databases && result.pg_databases !== 'N/A' && typeof result.pg_databases === 'string') {
            html += '<div style="margin-top: 1rem;">';
            html += '<h6 style="color: var(--txt); font-size: 0.95rem; margin-bottom: 0.75rem;">🗄️ Veritabanları</h6>';
            
            // Eğer boyut bilgisi varsa (parantez içinde)
            if (typeof result.pg_databases === 'string' && result.pg_databases.includes('(') && result.pg_databases.includes(')')) {
              // Database ismi (boyut) formatında
              const databases = result.pg_databases.split(',').map(db => db.trim());
              databases.forEach(db => {
                if (db && db !== 'database' && !db.includes('alınamadı')) {
                  // Database ismi ve boyutunu ayır
                  const match = db.match(/^(.+?)\s*\((.+?)\)$/);
                  if (match) {
                    const dbName = match[1].trim();
                    const dbSize = match[2].trim();
                    
                    html += '<div style="background: var(--hover); border-radius: 0.5rem; padding: 0.75rem; margin-bottom: 0.5rem; border-left: 3px solid #3b82f6;">';
                    html += '<div style="display: flex; justify-content: space-between; align-items: center;">';
                    html += `<span style="font-weight: 600; color: var(--txt); font-family: monospace; font-size: 0.9rem;">${dbName}</span>`;
                    html += `<span style="background: rgba(59, 130, 246, 0.2); color: #3b82f6; padding: 0.25rem 0.75rem; border-radius: 0.5rem; font-size: 0.8rem; font-weight: 500;">${dbSize}</span>`;
                    html += '</div></div>';
                  } else {
                    // Normal badge formatı
                    html += `<span style="background: rgba(59, 130, 246, 0.2); color: #3b82f6; border: 1px solid rgba(59, 130, 246, 0.3); padding: 0.35rem 0.85rem; border-radius: 0.5rem; font-size: 0.9rem; font-weight: 500; font-family: monospace;">${db}</span>`;
                  }
                }
              });
            } else {
              // Eski format - sadece isimler (badge formatı)
              html += '<div style="display: flex; flex-wrap: wrap; gap: 0.5rem;">';
              const databases = result.pg_databases.split(',').map(db => db.trim());
              databases.forEach(db => {
                if (db && !db.includes('alınamadı')) {
                  html += `<span style="background: rgba(59, 130, 246, 0.2); color: #3b82f6; border: 1px solid rgba(59, 130, 246, 0.3); padding: 0.35rem 0.85rem; border-radius: 0.5rem; font-size: 0.9rem; font-weight: 500; font-family: monospace;">${db}</span>`;
                }
              });
              html += '</div>';
            }
            html += '</div>';
          }
          
          // PostgreSQL Ayarları
          html += '<h6 class="mt-3" style="color: var(--txt); font-size: 0.95rem;">📊 PostgreSQL Ayarları</h6>';
          html += '<div class="detail-grid">';
          html += `<div class="detail-row"><span class="detail-label">Shared Buffers:</span><span class="detail-value">${result.pg_shared_buffers || 'N/A'}</span></div>`;
          html += `<div class="detail-row"><span class="detail-label">Work Mem:</span><span class="detail-value">${result.pg_work_mem || 'N/A'}</span></div>`;
          html += `<div class="detail-row"><span class="detail-label">Effective Cache Size:</span><span class="detail-value">${result.pg_effective_cache_size || 'N/A'}</span></div>`;
          html += `<div class="detail-row"><span class="detail-label">Maintenance Work Mem:</span><span class="detail-value">${result.pg_maintenance_work_mem || 'N/A'}</span></div>`;
          html += `<div class="detail-row"><span class="detail-label">WAL Level:</span><span class="detail-value">${result.pg_wal_level || 'N/A'}</span></div>`;
          html += `<div class="detail-row"><span class="detail-label">Archive Mode:</span><span class="detail-value">${result.pg_archive_mode || 'N/A'}</span></div>`;
          html += `<div class="detail-row" style="grid-column: 1 / -1;"><span class="detail-label">Replication Slots:</span><span class="detail-value" style="font-size: 0.85rem;">${result.pg_replication_slots || 'N/A'}</span></div>`;
          html += '</div>';
          
          // PostgreSQL Backup Araçları
          html += '<h6 class="mt-4" style="color: var(--txt); font-size: 0.95rem; margin-bottom: 0.75rem;">💾 PostgreSQL Backup Araçları</h6>';
          
          // pgBackRest
          html += '<div style="background: var(--hover); border-radius: 0.5rem; padding: 0.75rem; margin-bottom: 0.5rem; border-left: 3px solid #3b82f6;">';
          html += '<div style="display: flex; justify-content: space-between; align-items: center;">';
          html += '<span style="font-weight: 600; font-size: 0.9rem;">🔵 pgBackRest</span>';
          const pgbackrestBadge = result.pgbackrest_status === 'Var' ? 
            '<span style="background: rgba(16, 185, 129, 0.2); color: #10b981; padding: 0.25rem 0.5rem; border-radius: 0.25rem; font-size: 0.75rem; font-weight: 600;">KURULU</span>' :
            '<span style="background: rgba(107, 114, 128, 0.2); color: #6b7280; padding: 0.25rem 0.5rem; border-radius: 0.25rem; font-size: 0.75rem; font-weight: 600;">YOK</span>';
          html += pgbackrestBadge;
          html += '</div>';
          if (result.pgbackrest_details && result.pgbackrest_details !== 'Yok' && result.pgbackrest_details !== 'N/A' && typeof result.pgbackrest_details === 'string') {
            html += `<div style="margin-top: 0.5rem; background: var(--panel); padding: 0.75rem; border-radius: 0.25rem; border: 1px solid var(--border);">`;
            
            // Satır satır parse edelim ve güzel gösterelim
            const lines = result.pgbackrest_details.split('\n');
            lines.forEach(line => {
              if (line.trim()) {
                let lineColor = 'var(--txt)';
                let lineWeight = 'normal';
                let leftBorder = '';
                
                // Stanza satırı
                if (line.includes('stanza:')) {
                  lineWeight = '600';
                  lineColor = '#3b82f6';
                  leftBorder = 'border-left: 3px solid #3b82f6; padding-left: 0.5rem;';
                }
                // Status satırı
                else if (line.includes('status:')) {
                  if (line.includes('ok')) {
                    lineColor = '#10b981';
                  } else if (line.includes('error')) {
                    lineColor = '#ef4444';
                  }
                }
                // Error satırları
                else if (line.includes('error') || line.includes('Error')) {
                  lineColor = '#ef4444';
                }
                // Db satırı
                else if (line.includes('db (')) {
                  lineColor = '#f59e0b';
                }
                
                html += `<div style="font-size: 0.8rem; color: ${lineColor}; font-family: monospace; line-height: 1.6; font-weight: ${lineWeight}; ${leftBorder}">${line}</div>`;
              }
            });
            
            html += '</div>';
          }
          html += '</div>';
          
          // pg_probackup
          html += '<div style="background: var(--hover); border-radius: 0.5rem; padding: 0.75rem; margin-bottom: 0.5rem; border-left: 3px solid #f59e0b;">';
          html += '<div style="display: flex; justify-content: space-between; align-items: center;">';
          html += '<span style="font-weight: 600; font-size: 0.9rem;">🟡 pg_probackup</span>';
          const pgprobackupBadge = result.pg_probackup_status === 'Var' ?
            '<span style="background: rgba(16, 185, 129, 0.2); color: #10b981; padding: 0.25rem 0.5rem; border-radius: 0.25rem; font-size: 0.75rem; font-weight: 600;">KURULU</span>' :
            '<span style="background: rgba(107, 114, 128, 0.2); color: #6b7280; padding: 0.25rem 0.5rem; border-radius: 0.25rem; font-size: 0.75rem; font-weight: 600;">YOK</span>';
          html += pgprobackupBadge;
          html += '</div>';
          if (result.pg_probackup_details && result.pg_probackup_details !== 'Yok' && result.pg_probackup_details !== 'N/A' && typeof result.pg_probackup_details === 'string') {
            html += `<div style="margin-top: 0.5rem; background: var(--panel); padding: 0.75rem; border-radius: 0.25rem; border: 1px solid var(--border);">`;
            html += `<div style="font-size: 0.8rem; color: var(--txt); font-family: monospace; white-space: pre-wrap; line-height: 1.6;">${result.pg_probackup_details}</div>`;
            html += '</div>';
          }
          html += '</div>';
          
          // pgBarman
          html += '<div style="background: var(--hover); border-radius: 0.5rem; padding: 0.75rem; margin-bottom: 0.5rem; border-left: 3px solid #8b5cf6;">';
          html += '<div style="display: flex; justify-content: space-between; align-items: center;">';
          html += '<span style="font-weight: 600; font-size: 0.9rem;">🟣 pgBarman</span>';
          const pgbarmanBadge = result.pgbarman_status === 'Var' ?
            '<span style="background: rgba(16, 185, 129, 0.2); color: #10b981; padding: 0.25rem 0.5rem; border-radius: 0.25rem; font-size: 0.75rem; font-weight: 600;">KURULU</span>' :
            '<span style="background: rgba(107, 114, 128, 0.2); color: #6b7280; padding: 0.25rem 0.5rem; border-radius: 0.25rem; font-size: 0.75rem; font-weight: 600;">YOK</span>';
          html += pgbarmanBadge;
          html += '</div>';
          if (result.pgbarman_details && result.pgbarman_details !== 'Yok' && result.pgbarman_details !== 'N/A' && typeof result.pgbarman_details === 'string') {
            html += `<div style="margin-top: 0.5rem; background: var(--panel); padding: 0.75rem; border-radius: 0.25rem; border: 1px solid var(--border);">`;
            html += `<div style="font-size: 0.8rem; color: var(--txt); font-family: monospace; white-space: pre-wrap; line-height: 1.6;">${result.pgbarman_details}</div>`;
            html += '</div>';
          }
          html += '</div>';
          
          html += '</div>';
        }
        
        // High Availability Tools
        const haToolsExist = (result.patroni_status && result.patroni_status !== 'Yok' && result.patroni_status !== 'N/A') ||
                             (result.repmgr_status && result.repmgr_status !== 'Yok' && result.repmgr_status !== 'N/A') ||
                             (result.paf_status && result.paf_status !== 'Yok' && result.paf_status !== 'N/A') ||
                             (result.citus_status && result.citus_status !== 'Yok' && result.citus_status !== 'N/A') ||
                             (result.streaming_replication_status && result.streaming_replication_status !== 'N/A' && result.streaming_replication_status !== 'Yok (Standalone)');
        
        if (haToolsExist) {
          html += '<div class="detail-section">';
          html += '<h5 class="detail-section-title">🔄 High Availability ve Replication</h5>';
          
          // Streaming Replication
          if (result.streaming_replication_status && result.streaming_replication_status !== 'N/A' && result.streaming_replication_status !== 'Yok (Standalone)') {
            const isMaster = result.streaming_replication_status.includes('Master');
            const borderColor = isMaster ? '#10b981' : '#06b6d4';
            const bgColor = isMaster ? 'rgba(16, 185, 129, 0.2)' : 'rgba(6, 182, 212, 0.2)';
            const icon = isMaster ? '📤' : '📥';
            
            html += `<div style="background: var(--hover); border-radius: 0.5rem; padding: 0.75rem; margin-bottom: 0.75rem; border-left: 3px solid ${borderColor};">`;
            html += '<div style="display: flex; justify-content: space-between; align-items: center;">';
            html += `<span style="font-weight: 600; font-size: 0.95rem;">${icon} Streaming Replication</span>`;
            html += `<span style="background: ${bgColor}; color: ${borderColor}; padding: 0.25rem 0.5rem; border-radius: 0.25rem; font-size: 0.75rem; font-weight: 600;">${result.streaming_replication_status}</span>`;
            html += '</div>';
            if (result.streaming_replication_details && result.streaming_replication_details !== 'N/A') {
              html += `<div style="margin-top: 0.5rem; background: var(--panel); padding: 0.75rem; border-radius: 0.25rem; border: 1px solid var(--border); font-size: 0.85rem; font-family: monospace; white-space: pre-wrap; line-height: 1.6;">${result.streaming_replication_details}</div>`;
            }
            html += '</div>';
          }
          
          // Patroni
          if (result.patroni_status && result.patroni_status !== 'Yok') {
            html += '<div style="background: var(--hover); border-radius: 0.5rem; padding: 0.75rem; margin-bottom: 0.75rem; border-left: 3px solid #10b981;">';
            html += '<div style="display: flex; justify-content: space-between; align-items: center;">';
            html += '<span style="font-weight: 600; font-size: 0.95rem;">🟢 Patroni (HA Cluster Manager)</span>';
            html += '<span style="background: rgba(16, 185, 129, 0.2); color: #10b981; padding: 0.25rem 0.5rem; border-radius: 0.25rem; font-size: 0.75rem; font-weight: 600;">KURULU</span>';
            html += '</div>';
            if (result.patroni_details && result.patroni_details !== 'N/A') {
              html += `<div style="margin-top: 0.5rem; background: var(--panel); padding: 0.75rem; border-radius: 0.25rem; border: 1px solid var(--border); font-size: 0.85rem; font-family: monospace; white-space: pre-wrap; line-height: 1.6;">${result.patroni_details}</div>`;
            }
            html += '</div>';
          }
          
          // Repmgr
          if (result.repmgr_status && result.repmgr_status !== 'Yok') {
            html += '<div style="background: var(--hover); border-radius: 0.5rem; padding: 0.75rem; margin-bottom: 0.75rem; border-left: 3px solid #3b82f6;">';
            html += '<div style="display: flex; justify-content: space-between; align-items: center;">';
            html += '<span style="font-weight: 600; font-size: 0.95rem;">🔵 Repmgr (Replication Manager)</span>';
            html += '<span style="background: rgba(59, 130, 246, 0.2); color: #3b82f6; padding: 0.25rem 0.5rem; border-radius: 0.25rem; font-size: 0.75rem; font-weight: 600;">KURULU</span>';
            html += '</div>';
            if (result.repmgr_details && result.repmgr_details !== 'N/A') {
              html += `<div style="margin-top: 0.5rem; background: var(--panel); padding: 0.75rem; border-radius: 0.25rem; border: 1px solid var(--border); font-size: 0.85rem; font-family: monospace; white-space: pre-wrap; line-height: 1.6;">${result.repmgr_details}</div>`;
            }
            html += '</div>';
          }
          
          // PAF/Pacemaker
          if (result.paf_status && result.paf_status !== 'Yok') {
            html += '<div style="background: var(--hover); border-radius: 0.5rem; padding: 0.75rem; margin-bottom: 0.75rem; border-left: 3px solid #f59e0b;">';
            html += '<div style="display: flex; justify-content: space-between; align-items: center;">';
            html += '<span style="font-weight: 600; font-size: 0.95rem;">🟡 PAF / Pacemaker (Cluster Manager)</span>';
            html += '<span style="background: rgba(245, 158, 11, 0.2); color: #f59e0b; padding: 0.25rem 0.5rem; border-radius: 0.25rem; font-size: 0.75rem; font-weight: 600;">KURULU</span>';
            html += '</div>';
            if (result.paf_details && result.paf_details !== 'N/A') {
              html += `<div style="margin-top: 0.5rem; background: var(--panel); padding: 0.75rem; border-radius: 0.25rem; border: 1px solid var(--border); font-size: 0.85rem; font-family: monospace; white-space: pre-wrap; line-height: 1.6;">${result.paf_details}</div>`;
            }
            html += '</div>';
          }
          
          // Citus
          if (result.citus_status && result.citus_status !== 'Yok') {
            html += '<div style="background: var(--hover); border-radius: 0.5rem; padding: 0.75rem; margin-bottom: 0.75rem; border-left: 3px solid #8b5cf6;">';
            html += '<div style="display: flex; justify-content: space-between; align-items: center;">';
            html += '<span style="font-weight: 600; font-size: 0.95rem;">🟣 Citus (Distributed PostgreSQL)</span>';
            const citusStatusText = result.citus_status.includes('extension') ? 'EXTENSION AKTİF' : 'KURULU';
            html += `<span style="background: rgba(139, 92, 246, 0.2); color: #8b5cf6; padding: 0.25rem 0.5rem; border-radius: 0.25rem; font-size: 0.75rem; font-weight: 600;">${citusStatusText}</span>`;
            html += '</div>';
            if (result.citus_details && result.citus_details !== 'N/A') {
              html += `<div style="margin-top: 0.5rem; background: var(--panel); padding: 0.75rem; border-radius: 0.25rem; border: 1px solid var(--border); font-size: 0.85rem; font-family: monospace; white-space: pre-wrap; line-height: 1.6;">${result.citus_details}</div>`;
            }
            html += '</div>';
          }
          
          html += '</div>';
        }
        
          modalBody.innerHTML = html;
          
          // Show modal
          const modal = new bootstrap.Modal(document.getElementById('detailModal'));
          modal.show();
          
        } catch (error) {
          console.error('[ERROR] showDetails exception:', error);
          alert('Detaylar gösterilirken hata oluştu: ' + error.message + '\\n\\nBrowser console\'una bakın (F12)');
        }
      }

      // History deletion functions
      function updateDeleteButton() {
        const checkboxes = document.querySelectorAll('.history-checkbox:checked');
        const deleteBtn = document.getElementById('deleteSelectedBtn');
        const countSpan = document.getElementById('selectedHistoryCount');
        
        if (checkboxes && countSpan) {
          countSpan.textContent = checkboxes.length;
        }
        
        if (deleteBtn) {
          deleteBtn.disabled = checkboxes.length === 0;
        }
      }
      
      function selectAllHistory() {
        const selectAllCheckbox = document.getElementById('selectAllCheckbox');
        const checkboxes = document.querySelectorAll('.history-checkbox');
        
        checkboxes.forEach(cb => {
          cb.checked = selectAllCheckbox.checked;
        });
        
        updateDeleteButton();
      }
      
      async function deleteSingleHistory(id, hostname) {
        if (!confirm(`"${hostname}" sunucusunun healthcheck kaydını silmek istediğinize emin misiniz?`)) {
          return;
        }
        
        try {
          const response = await fetch(`/api/healthcheck/delete/${id}`, {
            method: 'DELETE'
          });
          
          if (response.ok) {
            alert('Kayıt başarıyla silindi!');
            window.location.reload();
          } else {
            const data = await response.json();
            alert('Silme işlemi başarısız: ' + (data.error || 'Bilinmeyen hata'));
          }
        } catch (error) {
          console.error('Delete error:', error);
          alert('Silme işlemi sırasında hata oluştu: ' + error.message);
        }
      }
      
      async function deleteSelectedHistory() {
        const checkboxes = document.querySelectorAll('.history-checkbox:checked');
        const ids = Array.from(checkboxes).map(cb => cb.value);
        
        if (ids.length === 0) {
          alert('Lütfen silmek istediğiniz kayıtları seçin!');
          return;
        }
        
        if (!confirm(`${ids.length} adet healthcheck kaydını silmek istediğinize emin misiniz? Bu işlem geri alınamaz!`)) {
          return;
        }
        
        try {
          const response = await fetch('/api/healthcheck/delete-multiple', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json'
            },
            body: JSON.stringify({ ids: ids })
          });
          
          if (response.ok) {
            const data = await response.json();
            alert(`${data.deleted_count} kayıt başarıyla silindi!`);
            window.location.reload();
          } else {
            const data = await response.json();
            alert('Silme işlemi başarısız: ' + (data.error || 'Bilinmeyen hata'));
          }
        } catch (error) {
          console.error('Delete error:', error);
          alert('Silme işlemi sırasında hata oluştu: ' + error.message);
        }
      }

      // Initialize theme on page load
      document.addEventListener('DOMContentLoaded', function() {
        initTheme();
        
        const themeToggle = document.getElementById('themeToggle');
        if (themeToggle) {
          themeToggle.addEventListener('click', toggleTheme);
        }
        
        // Add event listeners to checkboxes
        const checkboxes = document.querySelectorAll('.server-checkbox');
        checkboxes.forEach(cb => {
          cb.addEventListener('change', updateSelectedCount);
        });
        
        // Update delete button state on page load
        updateDeleteButton();
      });
    </script>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
  </body>
</html>
"""

# Healthcheck Detay Sayfası Template
TEMPLATE_HEALTHCHECK_DETAIL = r"""
<!doctype html>
<html lang="tr">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Healthcheck Detay</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
      :root[data-theme="dark"] {
        --bg: #0f1419;
        --bg-gradient-start: #0a0e13;
        --bg-gradient-end: #0f1419;
        --panel: #1a1f26;
        --hover: #242b36;
        --border: #2d3748;
        --txt: #e2e8f0;
        --txt-secondary: #94a3b8;
        --accent-blue: #3b82f6;
        --accent-green: #10b981;
        --accent-purple: #8b5cf6;
        --accent-orange: #f59e0b;
        --accent-red: #ef4444;
        --accent-cyan: #06b6d4;
      }
      :root[data-theme="light"] {
        --bg: #f8fafc;
        --bg-gradient-start: #f1f5f9;
        --bg-gradient-end: #f8fafc;
        --panel: #ffffff;
        --hover: #f1f5f9;
        --border: #e2e8f0;
        --txt: #1e293b;
        --txt-secondary: #64748b;
        --accent-blue: #3b82f6;
        --accent-green: #10b981;
        --accent-purple: #8b5cf6;
        --accent-orange: #f59e0b;
        --accent-red: #ef4444;
        --accent-cyan: #06b6d4;
      }
      * {
        margin: 0;
        padding: 0;
        box-sizing: border-box;
      }
      body {
        background: linear-gradient(180deg, var(--bg-gradient-start), var(--bg-gradient-end));
        color: var(--txt);
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        min-height: 100vh;
        transition: all 0.3s ease;
      }
      
      /* Navbar */
      .navbar {
        background: var(--panel);
        border-bottom: 1px solid var(--border);
        padding: 1.25rem 2rem;
        box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        position: sticky;
        top: 0;
        z-index: 100;
        backdrop-filter: blur(10px);
      }
      
      .back-button {
        display: inline-flex;
        align-items: center;
        gap: 0.5rem;
        padding: 0.625rem 1.25rem;
        background: linear-gradient(135deg, var(--accent-blue), var(--accent-cyan));
        border: none;
        border-radius: 0.75rem;
        color: white;
        text-decoration: none;
        font-weight: 500;
        transition: all 0.3s ease;
        box-shadow: 0 4px 12px rgba(59, 130, 246, 0.3);
      }
      .back-button:hover {
        transform: translateY(-2px);
        box-shadow: 0 6px 16px rgba(59, 130, 246, 0.4);
        color: white;
      }
      
      /* Theme Toggle */
      #themeToggle {
        background: var(--hover);
        border: 1px solid var(--border);
        border-radius: 0.75rem;
        padding: 0.625rem 1rem;
        cursor: pointer;
        transition: all 0.3s ease;
        font-size: 1.25rem;
      }
      #themeToggle:hover {
        background: var(--panel);
        transform: scale(1.05);
      }
      
      .detail-container {
        max-width: 1400px;
        margin: 2rem auto;
        padding: 0 2rem 4rem 2rem;
      }
      
      /* Header Card */
      .detail-header {
        background: linear-gradient(135deg, var(--accent-blue), var(--accent-purple));
        border-radius: 1.5rem;
        padding: 2.5rem;
        margin-bottom: 2rem;
        box-shadow: 0 8px 32px rgba(0,0,0,0.2);
        color: white;
        position: relative;
        overflow: hidden;
      }
      .detail-header::before {
        content: '';
        position: absolute;
        top: 0;
        right: 0;
        width: 300px;
        height: 300px;
        background: radial-gradient(circle, rgba(255,255,255,0.1) 0%, transparent 70%);
        border-radius: 50%;
        transform: translate(30%, -30%);
      }
      .detail-header h1 {
        font-size: 2.5rem;
        font-weight: 700;
        margin-bottom: 0.75rem;
        text-shadow: 0 2px 8px rgba(0,0,0,0.2);
      }
      .detail-header p {
        opacity: 0.9;
        font-size: 1.1rem;
      }
      
      .status-badge {
        display: inline-flex;
        align-items: center;
        gap: 0.5rem;
        padding: 0.75rem 1.5rem;
        border-radius: 2rem;
        font-weight: 600;
        font-size: 1rem;
        box-shadow: 0 4px 12px rgba(0,0,0,0.15);
      }
      .status-badge.success {
        background: rgba(255, 255, 255, 0.95);
        color: var(--accent-green);
      }
      .status-badge.error {
        background: rgba(255, 255, 255, 0.95);
        color: var(--accent-red);
      }
      
      /* Section Cards */
      .detail-section {
        background: var(--panel);
        border-radius: 1.25rem;
        padding: 2rem;
        margin-bottom: 1.5rem;
        border: 1px solid var(--border);
        box-shadow: 0 4px 16px rgba(0,0,0,0.05);
        transition: all 0.3s ease;
      }
      .detail-section:hover {
        transform: translateY(-4px);
        box-shadow: 0 8px 24px rgba(0,0,0,0.1);
      }
      
      .detail-section-title {
        font-size: 1.5rem;
        font-weight: 700;
        margin-bottom: 1.5rem;
        padding-bottom: 1rem;
        border-bottom: 3px solid var(--border);
        display: flex;
        align-items: center;
        gap: 0.75rem;
      }
      
      /* Color coded section titles */
      .section-system { border-left: 4px solid var(--accent-blue); }
      .section-cpu { border-left: 4px solid var(--accent-purple); }
      .section-ram { border-left: 4px solid var(--accent-green); }
      .section-disk { border-left: 4px solid var(--accent-cyan); }
      .section-postgres { border-left: 4px solid #336791; }
      .section-ha { border-left: 4px solid var(--accent-orange); }
      .section-network { border-left: 4px solid var(--accent-cyan); }
      .section-services { border-left: 4px solid var(--accent-purple); }
      
      .detail-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
        gap: 1rem;
      }
      
      .detail-row {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 1rem;
        background: var(--hover);
        border-radius: 0.75rem;
        border: 1px solid var(--border);
        transition: all 0.2s ease;
      }
      .detail-row:hover {
        background: var(--panel);
        border-color: var(--accent-blue);
        transform: translateX(4px);
      }
      
      .detail-label {
        font-weight: 600;
        color: var(--txt-secondary);
        font-size: 0.95rem;
      }
      
      .detail-value {
        color: var(--txt);
        font-weight: 500;
        text-align: right;
        word-break: break-word;
      }
      
      /* Info Cards */
      .info-card {
        background: linear-gradient(135deg, var(--hover), var(--panel));
        padding: 1.5rem;
        border-radius: 1rem;
        border: 1px solid var(--border);
        margin-bottom: 1rem;
      }
      
      .info-card h6 {
        font-weight: 700;
        margin-bottom: 1rem;
        font-size: 1.1rem;
        color: var(--txt);
        display: flex;
        align-items: center;
        gap: 0.5rem;
      }
      
      /* Pre/Code styling */
      pre {
        background: var(--hover);
        padding: 1.25rem;
        border-radius: 0.75rem;
        overflow-x: auto;
        white-space: pre-wrap;
        word-wrap: break-word;
        border: 1px solid var(--border);
        font-family: 'Fira Code', 'Courier New', monospace;
        font-size: 0.9rem;
        line-height: 1.6;
        color: var(--txt);
        box-shadow: inset 0 2px 8px rgba(0,0,0,0.05);
      }
      
      /* Badge styles */
      .badge {
        padding: 0.5rem 1rem;
        border-radius: 0.5rem;
        font-weight: 600;
        font-size: 0.875rem;
      }
      .badge.bg-success {
        background: linear-gradient(135deg, var(--accent-green), #059669) !important;
        box-shadow: 0 2px 8px rgba(16, 185, 129, 0.3);
      }
      .badge.bg-secondary {
        background: linear-gradient(135deg, #6b7280, #4b5563) !important;
      }
      
      /* HA Status badges */
      .ha-badge {
        display: inline-block;
        padding: 0.5rem 1rem;
        border-radius: 0.75rem;
        font-weight: 600;
        margin-right: 0.5rem;
        margin-bottom: 0.5rem;
      }
      .ha-badge-green { background: rgba(16, 185, 129, 0.2); color: var(--accent-green); border: 2px solid var(--accent-green); }
      .ha-badge-blue { background: rgba(59, 130, 246, 0.2); color: var(--accent-blue); border: 2px solid var(--accent-blue); }
      .ha-badge-orange { background: rgba(245, 158, 11, 0.2); color: var(--accent-orange); border: 2px solid var(--accent-orange); }
      .ha-badge-purple { background: rgba(139, 92, 246, 0.2); color: var(--accent-purple); border: 2px solid var(--accent-purple); }
      
      /* Scrollbar */
      ::-webkit-scrollbar {
        width: 10px;
        height: 10px;
      }
      ::-webkit-scrollbar-track {
        background: var(--hover);
        border-radius: 5px;
      }
      ::-webkit-scrollbar-thumb {
        background: var(--border);
        border-radius: 5px;
      }
      ::-webkit-scrollbar-thumb:hover {
        background: var(--accent-blue);
      }
      
      /* Animations */
      @keyframes fadeIn {
        from { opacity: 0; transform: translateY(20px); }
        to { opacity: 1; transform: translateY(0); }
      }
      .detail-section {
        animation: fadeIn 0.5s ease-out forwards;
      }
      .detail-section:nth-child(1) { animation-delay: 0.1s; }
      .detail-section:nth-child(2) { animation-delay: 0.15s; }
      .detail-section:nth-child(3) { animation-delay: 0.2s; }
      .detail-section:nth-child(4) { animation-delay: 0.25s; }
      .detail-section:nth-child(5) { animation-delay: 0.3s; }
      
      /* Modern Table Styles */
      .modern-table {
        width: 100%;
        border-collapse: separate;
        border-spacing: 0;
        margin-top: 1rem;
      }
      .modern-table thead {
        background: linear-gradient(135deg, var(--accent-blue), var(--accent-cyan));
        color: white;
      }
      .modern-table thead th {
        padding: 1rem;
        text-align: left;
        font-weight: 600;
        font-size: 0.95rem;
        border: none;
      }
      .modern-table thead th:first-child {
        border-top-left-radius: 0.75rem;
      }
      .modern-table thead th:last-child {
        border-top-right-radius: 0.75rem;
      }
      .modern-table tbody tr {
        background: var(--hover);
        border-bottom: 1px solid var(--border);
        transition: all 0.2s ease;
      }
      .modern-table tbody tr:hover {
        background: var(--panel);
        transform: scale(1.01);
        box-shadow: 0 2px 8px rgba(0,0,0,0.1);
      }
      .modern-table tbody tr:last-child td:first-child {
        border-bottom-left-radius: 0.75rem;
      }
      .modern-table tbody tr:last-child td:last-child {
        border-bottom-right-radius: 0.75rem;
      }
      .modern-table tbody td {
        padding: 1rem;
        border: none;
        color: var(--txt);
      }
      
      /* Process List Styles */
      .process-list {
        display: flex;
        flex-direction: column;
        gap: 0.75rem;
        margin-top: 1rem;
      }
      .process-item {
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 1rem;
        background: var(--hover);
        border-radius: 0.75rem;
        border-left: 4px solid var(--accent-purple);
        transition: all 0.2s ease;
      }
      .process-item:hover {
        background: var(--panel);
        transform: translateX(8px);
        box-shadow: 0 4px 12px rgba(0,0,0,0.1);
      }
      .process-name {
        flex: 1;
        font-weight: 500;
        color: var(--txt);
        font-family: 'Fira Code', monospace;
        font-size: 0.9rem;
      }
      .process-usage {
        display: flex;
        align-items: center;
        gap: 0.75rem;
      }
      .usage-bar {
        width: 120px;
        height: 8px;
        background: var(--border);
        border-radius: 4px;
        overflow: hidden;
        position: relative;
      }
      .usage-fill {
        height: 100%;
        background: linear-gradient(90deg, var(--accent-green), var(--accent-cyan));
        border-radius: 4px;
        transition: width 0.3s ease;
      }
      .usage-fill.high {
        background: linear-gradient(90deg, var(--accent-orange), var(--accent-red));
      }
      .usage-text {
        font-weight: 600;
        color: var(--accent-blue);
        min-width: 50px;
        text-align: right;
      }
      
      /* Disk Item Styles */
      .disk-list {
        display: flex;
        flex-direction: column;
        gap: 1rem;
        margin-top: 1rem;
      }
      .disk-item {
        background: var(--hover);
        border-radius: 0.75rem;
        padding: 1.25rem;
        border: 1px solid var(--border);
        transition: all 0.2s ease;
      }
      .disk-item:hover {
        background: var(--panel);
        transform: translateY(-2px);
        box-shadow: 0 4px 12px rgba(0,0,0,0.1);
      }
      .disk-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 1rem;
      }
      .disk-device {
        font-weight: 700;
        color: var(--txt);
        font-size: 1.1rem;
      }
      .disk-mount {
        color: var(--txt-secondary);
        font-style: italic;
      }
      .disk-usage-bar {
        width: 100%;
        height: 12px;
        background: var(--border);
        border-radius: 6px;
        overflow: hidden;
        margin-top: 0.5rem;
        position: relative;
      }
      .disk-usage-fill {
        height: 100%;
        border-radius: 6px;
        transition: width 0.5s ease;
        background: linear-gradient(90deg, var(--accent-green), var(--accent-cyan));
      }
      .disk-usage-fill.warning {
        background: linear-gradient(90deg, var(--accent-orange), #f59e0b);
      }
      .disk-usage-fill.danger {
        background: linear-gradient(90deg, var(--accent-red), #dc2626);
      }
      .disk-stats {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
        gap: 0.75rem;
        margin-top: 1rem;
      }
      .disk-stat {
        display: flex;
        flex-direction: column;
      }
      .disk-stat-label {
        font-size: 0.85rem;
        color: var(--txt-secondary);
        margin-bottom: 0.25rem;
      }
      .disk-stat-value {
        font-weight: 600;
        color: var(--txt);
        font-size: 1rem;
      }
      
      /* Service List Styles */
      .service-list {
        display: flex;
        flex-direction: column;
        gap: 0.5rem;
        margin-top: 1rem;
      }
      .service-item {
        padding: 0.75rem 1rem;
        background: var(--hover);
        border-radius: 0.5rem;
        border-left: 4px solid var(--accent-green);
        display: flex;
        align-items: center;
        gap: 0.75rem;
        transition: all 0.2s ease;
      }
      .service-item:hover {
        background: var(--panel);
        transform: translateX(4px);
      }
      .service-item.failed {
        border-left-color: var(--accent-red);
      }
      .service-icon {
        font-size: 1.25rem;
      }
      .service-name {
        flex: 1;
        font-weight: 500;
        color: var(--txt);
        font-family: 'Fira Code', monospace;
        font-size: 0.9rem;
      }
      .service-status {
        font-size: 0.85rem;
        color: var(--txt-secondary);
      }
    </style>
  </head>
  <body>
    <!-- Navbar -->
    <nav class="navbar">
      <div style="display: flex; justify-content: space-between; align-items: center; width: 100%;">
        <div style="display: flex; align-items: center; gap: 1rem;">
          <h2 style="margin: 0; font-weight: 700; font-size: 1.5rem;">🏥 Healthcheck Detay</h2>
        </div>
        <div style="display: flex; align-items: center; gap: 1rem;">
          <button id="themeToggle" onclick="toggleTheme()">🌙</button>
          <a href="/healthcheck" class="back-button">
            <svg width="16" height="16" fill="currentColor" viewBox="0 0 16 16">
              <path fill-rule="evenodd" d="M15 8a.5.5 0 0 0-.5-.5H2.707l3.147-3.146a.5.5 0 1 0-.708-.708l-4 4a.5.5 0 0 0 0 .708l4 4a.5.5 0 0 0 .708-.708L2.707 8.5H14.5A.5.5 0 0 0 15 8z"/>
            </svg>
            Geri Dön
          </a>
        </div>
      </div>
    </nav>

    <div class="detail-container">
      <!-- Header -->
      <div class="detail-header">
        <div style="display: flex; justify-content: space-between; align-items: start; position: relative; z-index: 1;">
          <div>
            <h1>{{ record.hostname }}</h1>
            <p style="margin: 0; font-size: 1.1rem;">{{ record.ip }} • {{ record.created_at }}</p>
            <div style="margin-top: 1.5rem; padding-top: 1rem; border-top: 1px solid rgba(255,255,255,0.2);">
              <small style="opacity: 0.9; font-size: 1rem;">👤 Kontrol Eden: <strong>{{ record.checked_by_username }}</strong></small>
            </div>
          </div>
          <div>
            {% if record.status == 'success' %}
              <span class="status-badge success">✓ Başarılı</span>
            {% else %}
              <span class="status-badge error">✗ Hata</span>
            {% endif %}
          </div>
        </div>
      </div>

      <!-- Sistem Bilgileri -->
      <div class="detail-section section-system">
        <h5 class="detail-section-title">💻 Sistem Bilgileri</h5>
        <div class="detail-grid">
          <div class="detail-row"><span class="detail-label">İşletim Sistemi:</span><span class="detail-value">{{ record.os_info or 'N/A' }}</span></div>
          <div class="detail-row"><span class="detail-label">Kernel:</span><span class="detail-value">{{ record.kernel_version or 'N/A' }}</span></div>
          <div class="detail-row"><span class="detail-label">Mimari:</span><span class="detail-value">{{ record.architecture or 'N/A' }}</span></div>
          <div class="detail-row"><span class="detail-label">Son Açılış:</span><span class="detail-value">{{ record.last_boot or 'N/A' }}</span></div>
          <div class="detail-row"><span class="detail-label">Uptime:</span><span class="detail-value">{{ record.uptime or 'N/A' }}</span></div>
          <div class="detail-row"><span class="detail-label">Timezone:</span><span class="detail-value">{{ record.timezone or 'N/A' }}</span></div>
        </div>
        
        <!-- System Update Status -->
        {% if record.system_update_status and record.system_update_status != 'N/A' %}
        <div style="margin-top: 1.5rem;">
          {% if record.system_update_status == 'up-to-date' %}
            <div style="background: rgba(16, 185, 129, 0.1); border: 1px solid rgba(16, 185, 129, 0.3); border-radius: 0.75rem; padding: 1rem;">
              <div style="display: flex; align-items: center; gap: 0.75rem;">
                <span style="font-size: 1.5rem;">✓</span>
                <div>
                  <div style="font-weight: 600; color: #10b981; font-size: 1rem;">Sistem Güncellemeleri</div>
                  <div style="font-size: 0.9rem; color: var(--txt); margin-top: 0.25rem;">{{ record.system_update_message or 'Sistem güncel' }}</div>
                </div>
              </div>
            </div>
          {% elif record.system_update_status == 'updates-available' %}
            <div style="background: rgba(245, 158, 11, 0.1); border: 1px solid rgba(245, 158, 11, 0.3); border-radius: 0.75rem; padding: 1rem;">
              <div style="display: flex; align-items: center; gap: 0.75rem;">
                <span style="font-size: 1.5rem;">⚠️</span>
                <div>
                  <div style="font-weight: 600; color: #f59e0b; font-size: 1rem;">Sistem Güncellemeleri</div>
                  <div style="font-size: 0.9rem; color: var(--txt); margin-top: 0.25rem;">{{ record.system_update_message or 'Güncellemeler mevcut' }}</div>
                </div>
              </div>
            </div>
          {% else %}
            <div style="background: rgba(107, 114, 128, 0.1); border: 1px solid rgba(107, 114, 128, 0.3); border-radius: 0.75rem; padding: 1rem;">
              <div style="display: flex; align-items: center; gap: 0.75rem;">
                <span style="font-size: 1.5rem;">ℹ️</span>
                <div>
                  <div style="font-weight: 600; color: #6b7280; font-size: 1rem;">Sistem Güncellemeleri</div>
                  <div style="font-size: 0.9rem; color: var(--txt); margin-top: 0.25rem;">{{ record.system_update_message or 'Durum bilinmiyor' }}</div>
                </div>
              </div>
            </div>
          {% endif %}
        </div>
        {% endif %}
      </div>

      <!-- CPU Bilgileri -->
      <div class="detail-section section-cpu">
        <h5 class="detail-section-title">⚙️ CPU Bilgileri</h5>
        <div class="detail-grid">
          <div class="detail-row"><span class="detail-label">CPU:</span><span class="detail-value">{{ record.cpu_info or 'N/A' }}</span></div>
          {% if record.cpu_details and record.cpu_details != 'N/A' %}
          <div class="detail-row"><span class="detail-label">Detaylar:</span><span class="detail-value">{{ record.cpu_details }}</span></div>
          {% endif %}
          <div class="detail-row"><span class="detail-label">Load Average:</span><span class="detail-value">{{ record.load_average or 'N/A' }}</span></div>
        </div>
        {% if record.top_cpu_processes and record.top_cpu_processes != 'N/A' %}
        <div class="info-card" style="margin-top: 1.5rem;">
          <h6>📊 En Çok CPU Kullanan İşlemler</h6>
          <div class="process-list" id="cpuProcessList" data-processes="{{ record.top_cpu_processes }}"></div>
        </div>
        {% endif %}
      </div>

      <!-- RAM Bilgileri -->
      <div class="detail-section section-ram">
        <h5 class="detail-section-title">🧠 RAM Bilgileri</h5>
        <div class="detail-grid">
          <div class="detail-row"><span class="detail-label">Toplam:</span><span class="detail-value">{{ record.ram_total or 'N/A' }}</span></div>
          <div class="detail-row"><span class="detail-label">Kullanılan:</span><span class="detail-value">{{ record.ram_used or 'N/A' }}</span></div>
          <div class="detail-row"><span class="detail-label">Boş:</span><span class="detail-value">{{ record.ram_free or 'N/A' }}</span></div>
          <div class="detail-row"><span class="detail-label">Swap:</span><span class="detail-value">{{ record.swap_memory or 'N/A' }}</span></div>
        </div>
        {% if record.top_memory_processes and record.top_memory_processes != 'N/A' %}
        <div class="info-card" style="margin-top: 1.5rem;">
          <h6>📊 En Çok RAM Kullanan İşlemler</h6>
          <div class="process-list" id="ramProcessList" data-processes="{{ record.top_memory_processes }}"></div>
        </div>
        {% endif %}
      </div>

      <!-- Disk Bilgileri -->
      {% if record.disks and record.disks != '[]' %}
      <div class="detail-section section-disk">
        <h5 class="detail-section-title">💾 Disk Bilgileri</h5>
        <div class="detail-grid" style="margin-bottom: 1.5rem;">
          <div class="detail-row"><span class="detail-label">Disk Tipi:</span><span class="detail-value">{{ record.disk_type or 'N/A' }}</span></div>
          <div class="detail-row"><span class="detail-label">Yazma Hızı:</span><span class="detail-value">{{ record.disk_write_speed or 'N/A' }}</span></div>
          <div class="detail-row"><span class="detail-label">Okuma Hızı:</span><span class="detail-value">{{ record.disk_read_speed or 'N/A' }}</span></div>
        </div>
        <div class="disk-list" id="diskList" data-disks="{{ record.disks|e }}"></div>
      </div>
      {% endif %}

      <!-- PostgreSQL Bilgileri -->
      {% if record.postgresql_status == 'Var' %}
      <div class="detail-section section-postgres">
        <h5 class="detail-section-title">🐘 PostgreSQL Bilgileri</h5>
        <div class="detail-grid">
          <div class="detail-row"><span class="detail-label">Durum:</span><span class="detail-value"><span class="badge bg-success">{{ record.postgresql_status }}</span></span></div>
          <div class="detail-row"><span class="detail-label">Versiyon:</span><span class="detail-value">{{ record.postgresql_version or 'N/A' }}</span></div>
          <div class="detail-row"><span class="detail-label">Port:</span><span class="detail-value">{{ record.pg_port or 'N/A' }}</span></div>
          <div class="detail-row"><span class="detail-label">Data Directory:</span><span class="detail-value">{{ record.pg_data_directory or 'N/A' }}</span></div>
          <div class="detail-row"><span class="detail-label">Aktif Bağlantı:</span><span class="detail-value">{{ record.pg_connection_count or 'N/A' }}</span></div>
          <div class="detail-row"><span class="detail-label">Max Bağlantı:</span><span class="detail-value">{{ record.pg_max_connections or 'N/A' }}</span></div>
          <div class="detail-row"><span class="detail-label">Toplam Boyut:</span><span class="detail-value">{{ record.pg_total_size or 'N/A' }}</span></div>
          <div class="detail-row"><span class="detail-label">PostgreSQL Uptime:</span><span class="detail-value">{{ record.pg_uptime or 'N/A' }}</span></div>
          <div class="detail-row"><span class="detail-label">Replication:</span><span class="detail-value">{{ record.postgresql_replication or 'N/A' }}</span></div>
          <div class="detail-row"><span class="detail-label">pgBackRest:</span><span class="detail-value">{{ record.pgbackrest_status or 'N/A' }}</span></div>
        </div>
        
        <!-- PostgreSQL Ayarları -->
        <div class="info-card" style="margin-top: 1.5rem;">
          <h6>⚙️ PostgreSQL Ayarları</h6>
          <div class="detail-grid">
            <div class="detail-row"><span class="detail-label">Shared Buffers:</span><span class="detail-value">{{ record.pg_shared_buffers or 'N/A' }}</span></div>
            <div class="detail-row"><span class="detail-label">Work Mem:</span><span class="detail-value">{{ record.pg_work_mem or 'N/A' }}</span></div>
            <div class="detail-row"><span class="detail-label">Effective Cache Size:</span><span class="detail-value">{{ record.pg_effective_cache_size or 'N/A' }}</span></div>
            <div class="detail-row"><span class="detail-label">Maintenance Work Mem:</span><span class="detail-value">{{ record.pg_maintenance_work_mem or 'N/A' }}</span></div>
            <div class="detail-row"><span class="detail-label">WAL Level:</span><span class="detail-value">{{ record.pg_wal_level or 'N/A' }}</span></div>
            <div class="detail-row"><span class="detail-label">Archive Mode:</span><span class="detail-value">{{ record.pg_archive_mode or 'N/A' }}</span></div>
          </div>
        </div>

        <!-- Databases -->
        {% if record.pg_databases and record.pg_databases != 'N/A' %}
        <div class="info-card" style="margin-top: 1rem;">
          <h6>📁 Databases</h6>
          <pre>{{ record.pg_databases }}</pre>
        </div>
        {% endif %}
        
        <!-- PostgreSQL Backup Araçları -->
        <div class="info-card" style="margin-top: 1.5rem;">
          <h6>💾 PostgreSQL Backup Araçları</h6>
          
          <!-- pgBackRest -->
          <div style="background: var(--hover); border-radius: 0.75rem; padding: 1rem; margin-bottom: 0.75rem; border-left: 3px solid #3b82f6;">
            <div style="display: flex; justify-content: space-between; align-items: center;">
              <span style="font-weight: 600; font-size: 0.95rem;">🔵 pgBackRest</span>
              {% if record.pgbackrest_status == 'Var' %}
                <span style="background: rgba(16, 185, 129, 0.2); color: #10b981; padding: 0.35rem 0.75rem; border-radius: 0.5rem; font-size: 0.8rem; font-weight: 600;">KURULU</span>
              {% else %}
                <span style="background: rgba(107, 114, 128, 0.2); color: #6b7280; padding: 0.35rem 0.75rem; border-radius: 0.5rem; font-size: 0.8rem; font-weight: 600;">YOK</span>
              {% endif %}
            </div>
            {% if record.pgbackrest_details and record.pgbackrest_details not in ['Yok', 'N/A'] %}
              <div style="margin-top: 0.75rem; background: var(--panel); padding: 0.75rem; border-radius: 0.5rem; border: 1px solid var(--border);">
                <pre style="margin: 0; font-size: 0.85rem; line-height: 1.6;">{{ record.pgbackrest_details }}</pre>
              </div>
            {% endif %}
          </div>
          
          <!-- pg_probackup -->
          <div style="background: var(--hover); border-radius: 0.75rem; padding: 1rem; margin-bottom: 0.75rem; border-left: 3px solid #f59e0b;">
            <div style="display: flex; justify-content: space-between; align-items: center;">
              <span style="font-weight: 600; font-size: 0.95rem;">🟡 pg_probackup</span>
              {% if record.pg_probackup_status == 'Var' %}
                <span style="background: rgba(16, 185, 129, 0.2); color: #10b981; padding: 0.35rem 0.75rem; border-radius: 0.5rem; font-size: 0.8rem; font-weight: 600;">KURULU</span>
              {% else %}
                <span style="background: rgba(107, 114, 128, 0.2); color: #6b7280; padding: 0.35rem 0.75rem; border-radius: 0.5rem; font-size: 0.8rem; font-weight: 600;">YOK</span>
              {% endif %}
            </div>
            {% if record.pg_probackup_details and record.pg_probackup_details not in ['Yok', 'N/A'] %}
              <div style="margin-top: 0.75rem; background: var(--panel); padding: 0.75rem; border-radius: 0.5rem; border: 1px solid var(--border);">
                <pre style="margin: 0; font-size: 0.85rem; line-height: 1.6;">{{ record.pg_probackup_details }}</pre>
              </div>
            {% endif %}
          </div>
          
          <!-- pgBarman -->
          <div style="background: var(--hover); border-radius: 0.75rem; padding: 1rem; margin-bottom: 0; border-left: 3px solid #8b5cf6;">
            <div style="display: flex; justify-content: space-between; align-items: center;">
              <span style="font-weight: 600; font-size: 0.95rem;">🟣 pgBarman</span>
              {% if record.pgbarman_status == 'Var' %}
                <span style="background: rgba(16, 185, 129, 0.2); color: #10b981; padding: 0.35rem 0.75rem; border-radius: 0.5rem; font-size: 0.8rem; font-weight: 600;">KURULU</span>
              {% else %}
                <span style="background: rgba(107, 114, 128, 0.2); color: #6b7280; padding: 0.35rem 0.75rem; border-radius: 0.5rem; font-size: 0.8rem; font-weight: 600;">YOK</span>
              {% endif %}
            </div>
            {% if record.pgbarman_details and record.pgbarman_details not in ['Yok', 'N/A'] %}
              <div style="margin-top: 0.75rem; background: var(--panel); padding: 0.75rem; border-radius: 0.5rem; border: 1px solid var(--border);">
                <pre style="margin: 0; font-size: 0.85rem; line-height: 1.6;">{{ record.pgbarman_details }}</pre>
              </div>
            {% endif %}
          </div>
        </div>
      </div>
      {% endif %}

      <!-- High Availability Tools -->
      {% if (record.patroni_status and record.patroni_status == 'Var') or 
            (record.repmgr_status and record.repmgr_status == 'Var') or 
            (record.paf_status and record.paf_status == 'Var') or 
            (record.citus_status and record.citus_status != 'Yok') or 
            (record.streaming_replication_status and record.streaming_replication_status not in ['N/A', 'Yok (Standalone)']) %}
      <div class="detail-section section-ha">
        <h5 class="detail-section-title">🔄 High Availability ve Replication</h5>
        
        {% if record.patroni_status == 'Var' %}
        <div class="info-card">
          <h6><span class="ha-badge ha-badge-green">🟢 Patroni</span></h6>
          <pre>{{ record.patroni_details or 'N/A' }}</pre>
        </div>
        {% endif %}
        
        {% if record.repmgr_status == 'Var' %}
        <div class="info-card">
          <h6><span class="ha-badge ha-badge-blue">🔵 Repmgr</span></h6>
          <pre>{{ record.repmgr_details or 'N/A' }}</pre>
        </div>
        {% endif %}
        
        {% if record.paf_status == 'Var' %}
        <div class="info-card">
          <h6><span class="ha-badge ha-badge-orange">🟠 PAF/Pacemaker</span></h6>
          <pre>{{ record.paf_details or 'N/A' }}</pre>
        </div>
        {% endif %}
        
        {% if record.citus_status and record.citus_status != 'Yok' %}
        <div class="info-card">
          <h6><span class="ha-badge ha-badge-purple">🟣 Citus</span></h6>
          <pre>{{ record.citus_details or 'N/A' }}</pre>
        </div>
        {% endif %}
        
        {% if record.streaming_replication_status and record.streaming_replication_status not in ['N/A', 'Yok (Standalone)'] %}
        <div class="info-card">
          <h6><span class="ha-badge ha-badge-blue">📤 Streaming Replication</span></h6>
          <div class="detail-row" style="margin-bottom: 1rem;"><span class="detail-label">Durum:</span><span class="detail-value">{{ record.streaming_replication_status }}</span></div>
          <pre>{{ record.streaming_replication_details or 'N/A' }}</pre>
        </div>
        {% endif %}
      </div>
      {% endif %}

      <!-- Network Bilgileri -->
      <div class="detail-section section-network">
        <h5 class="detail-section-title">🌐 Network Bilgileri</h5>
        <div class="detail-grid">
          <div class="detail-row"><span class="detail-label">Network Info:</span><span class="detail-value">{{ record.network_info or 'N/A' }}</span></div>
          <div class="detail-row"><span class="detail-label">DNS Servers:</span><span class="detail-value">{{ record.dns_servers or 'N/A' }}</span></div>
          <div class="detail-row"><span class="detail-label">Total Connections:</span><span class="detail-value">{{ record.total_connections or 'N/A' }}</span></div>
        </div>
        
        <!-- Network Interfaces -->
        {% if record.network_interfaces and record.network_interfaces != 'N/A' %}
        <div class="info-card" style="margin-top: 1.5rem;">
          <h6>🔌 Network Interfaces</h6>
          <div id="networkInterfaces" data-interfaces="{{ record.network_interfaces }}"></div>
        </div>
        {% endif %}
        
        <!-- Listening Ports -->
        {% if record.listening_ports and record.listening_ports != 'N/A' %}
        <div class="info-card" style="margin-top: 1rem;">
          <h6>🔓 Dinlenen Portlar</h6>
          <div id="listeningPorts" data-ports="{{ record.listening_ports }}"></div>
        </div>
        {% endif %}
      </div>
      
      <!-- Kernel Parameters (PostgreSQL için önemli) -->
      {% if record.kernel_params and record.kernel_params not in ['{}', 'N/A'] %}
      <div class="detail-section section-system">
        <h5 class="detail-section-title">⚙️ Kernel Parametreleri (PostgreSQL için Kritik)</h5>
        <div id="kernelParams" data-params="{{ record.kernel_params|e }}"></div>
      </div>
      {% endif %}

      <!-- Servis Bilgileri -->
      <div class="detail-section section-services">
        <h5 class="detail-section-title">🔧 Servis Bilgileri</h5>
        {% if record.running_services and record.running_services != 'N/A' %}
        <div class="info-card">
          <h6>✅ Çalışan Servisler</h6>
          <div class="service-list" id="runningServicesList" data-services="{{ record.running_services }}"></div>
        </div>
        {% endif %}
        
        {% if record.failed_services and record.failed_services not in ['N/A', 'None'] %}
        <div class="info-card">
          <h6>⚠️ Başarısız Servisler</h6>
          <div class="service-list" id="failedServicesList" data-services="{{ record.failed_services }}"></div>
        </div>
        {% endif %}
      </div>

      <!-- Hata Mesajı -->
      {% if record.error_message and record.error_message != 'N/A' %}
      <div class="detail-section" style="border-left: 4px solid var(--accent-red); background: linear-gradient(135deg, rgba(239, 68, 68, 0.05), var(--panel));">
        <h5 class="detail-section-title" style="color: var(--accent-red);">❌ Hata Mesajı</h5>
        <pre style="border-left: 4px solid var(--accent-red);">{{ record.error_message }}</pre>
      </div>
      {% endif %}
    </div>

    <script>
      // Theme toggle function
      function toggleTheme() {
        const currentTheme = document.documentElement.getAttribute('data-theme');
        const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
        document.documentElement.setAttribute('data-theme', newTheme);
        
        const themeIcon = document.getElementById('themeToggle');
        if (themeIcon) {
          themeIcon.textContent = newTheme === 'dark' ? '🌙' : '☀️';
        }
        
        localStorage.setItem('theme', newTheme);
      }
      
      // Initialize theme on page load
      function initTheme() {
        const savedTheme = localStorage.getItem('theme') || 'dark';
        document.documentElement.setAttribute('data-theme', savedTheme);
        
        const themeIcon = document.getElementById('themeToggle');
        if (themeIcon) {
          themeIcon.textContent = savedTheme === 'dark' ? '🌙' : '☀️';
        }
      }
      
      // Parse and render process list
      function renderProcessList(elementId, type) {
        const element = document.getElementById(elementId);
        if (!element) return;
        
        const data = element.getAttribute('data-processes');
        if (!data || data === 'N/A') return;
        
        // Parse process data - format: "process1 12.4% | process2 0.3% | ..."
        const processes = data.split(' | ').map(p => {
          const parts = p.trim().split(' ');
          const percentage = parts[parts.length - 1].replace('%', '');
          const name = parts.slice(0, -1).join(' ');
          return { name, percentage: parseFloat(percentage) };
        }).filter(p => p.name && !isNaN(p.percentage));
        
        element.innerHTML = processes.map(proc => {
          const isHigh = proc.percentage > 50;
          const fillClass = isHigh ? 'high' : '';
          return `
            <div class="process-item">
              <div class="process-name">${proc.name}</div>
              <div class="process-usage">
                <div class="usage-bar">
                  <div class="usage-fill ${fillClass}" style="width: ${Math.min(proc.percentage, 100)}%"></div>
                </div>
                <div class="usage-text">${proc.percentage}%</div>
              </div>
            </div>
          `;
        }).join('');
      }
      
      // Parse and render disk list
      function renderDiskList() {
        const element = document.getElementById('diskList');
        if (!element) return;
        
        const data = element.getAttribute('data-disks');
        if (!data || data === '[]') return;
        
        try {
          const disks = JSON.parse(data);
          
          element.innerHTML = disks.map(disk => {
            const percentNum = parseInt(disk.percent.replace('%', ''));
            let fillClass = '';
            if (percentNum >= 90) fillClass = 'danger';
            else if (percentNum >= 70) fillClass = 'warning';
            
            return `
              <div class="disk-item">
                <div class="disk-header">
                  <div>
                    <div class="disk-device">💿 ${disk.device}</div>
                    <div class="disk-mount">📁 ${disk.mount}</div>
                  </div>
                  <div style="text-align: right;">
                    <div style="font-size: 1.5rem; font-weight: 700; color: var(--accent-blue);">${disk.percent}</div>
                    <div style="font-size: 0.85rem; color: var(--txt-secondary);">Kullanım</div>
                  </div>
                </div>
                <div class="disk-usage-bar">
                  <div class="disk-usage-fill ${fillClass}" style="width: ${disk.percent}"></div>
                </div>
                <div class="disk-stats">
                  <div class="disk-stat">
                    <div class="disk-stat-label">Toplam</div>
                    <div class="disk-stat-value">${disk.size}</div>
                  </div>
                  <div class="disk-stat">
                    <div class="disk-stat-label">Kullanılan</div>
                    <div class="disk-stat-value">${disk.used}</div>
                  </div>
                  <div class="disk-stat">
                    <div class="disk-stat-label">Boş</div>
                    <div class="disk-stat-value">${disk.avail}</div>
                  </div>
                </div>
              </div>
            `;
          }).join('');
        } catch (e) {
          console.error('Disk parsing error:', e);
          element.innerHTML = '<pre>' + data + '</pre>';
        }
      }
      
      // Parse and render service list
      function renderServiceList(elementId, isFailed) {
        const element = document.getElementById(elementId);
        if (!element) return;
        
        const data = element.getAttribute('data-services');
        if (!data || data === 'N/A' || data === 'None') return;
        
        // Parse services - format: "service1.service, service2.service" or detailed format with status
        let services = [];
        
        if (isFailed && data.includes('|||')) {
          // Failed services with detailed info
          services = data.split(' ||| ').map(s => {
            const parts = s.trim().split(' (');
            return {
              name: parts[0],
              status: parts[1] ? parts[1].replace(')', '') : 'failed'
            };
          });
        } else {
          // Simple format
          services = data.split(/,|\s+/).filter(s => s.trim()).map(s => ({
            name: s.trim(),
            status: isFailed ? 'failed' : 'active'
          }));
        }
        
        element.innerHTML = services.map(service => {
          const icon = isFailed ? '❌' : '✅';
          const failedClass = isFailed ? 'failed' : '';
          return `
            <div class="service-item ${failedClass}">
              <div class="service-icon">${icon}</div>
              <div class="service-name">${service.name}</div>
              ${service.status !== 'active' && service.status !== 'failed' ? 
                `<div class="service-status">${service.status}</div>` : ''}
            </div>
          `;
        }).join('');
      }
      
      // Render network interfaces
      function renderNetworkInterfaces() {
        const element = document.getElementById('networkInterfaces');
        if (!element) return;
        
        const data = element.getAttribute('data-interfaces');
        if (!data || data === 'N/A') return;
        
        const interfaces = data.split('\\n').filter(i => i.trim());
        element.innerHTML = interfaces.map(iface => {
          return `
            <div style="background: var(--hover); padding: 0.75rem; border-radius: 0.5rem; margin-bottom: 0.5rem; border-left: 3px solid #3b82f6; font-family: monospace; font-size: 0.9rem;">
              ${iface.trim()}
            </div>
          `;
        }).join('');
      }
      
      // Render listening ports
      function renderListeningPorts() {
        const element = document.getElementById('listeningPorts');
        if (!element) return;
        
        const data = element.getAttribute('data-ports');
        if (!data || data === 'N/A') return;
        
        const ports = data.split(',').map(p => p.trim()).filter(p => p);
        element.innerHTML = '<div style="display: flex; flex-wrap: wrap; gap: 0.5rem;">' + 
          ports.map(port => {
            const portNum = parseInt(port);
            let portColor = '#3b82f6';
            let portLabel = '';
            
            if (portNum === 22) { portColor = '#10b981'; portLabel = ' SSH'; }
            else if (portNum === 80) { portColor = '#f59e0b'; portLabel = ' HTTP'; }
            else if (portNum === 443) { portColor = '#f59e0b'; portLabel = ' HTTPS'; }
            else if (portNum === 5432) { portColor = '#3b82f6'; portLabel = ' PostgreSQL'; }
            else if (portNum === 3306) { portColor = '#ef4444'; portLabel = ' MySQL'; }
            else if (portNum === 8123) { portColor = '#8b5cf6'; portLabel = ' ClickHouse'; }
            
            return `<span style="background: ${portColor}; color: white; padding: 0.35rem 0.85rem; border-radius: 0.5rem; font-size: 0.9rem; font-weight: 500;">${port}${portLabel}</span>`;
          }).join('') + '</div>';
      }
      
      // Render kernel parameters
      function renderKernelParams() {
        const element = document.getElementById('kernelParams');
        if (!element) return;
        
        const data = element.getAttribute('data-params');
        if (!data || data === '{}' || data === 'N/A') return;
        
        try {
          const params = JSON.parse(data);
          
          let html = '';
          
          // Shared Memory
          html += '<div class="info-card">';
          html += '<h6>💾 Paylaşımlı Bellek (Shared Memory)</h6>';
          html += '<div class="detail-grid">';
          html += `<div class="detail-row"><span class="detail-label">SHMMAX:</span><span class="detail-value">${params.shmmax || 'N/A'}</span></div>`;
          html += `<div class="detail-row"><span class="detail-label">SHMALL:</span><span class="detail-value">${params.shmall || 'N/A'}</span></div>`;
          html += `<div class="detail-row"><span class="detail-label">SHMMNI:</span><span class="detail-value">${params.shmmni || 'N/A'}</span></div>`;
          html += '</div></div>';
          
          // Semaphore
          html += '<div class="info-card" style="margin-top: 1rem;">';
          html += '<h6>🔗 Semaphore Parametreleri</h6>';
          html += '<div class="detail-grid">';
          if (params.semmsl) html += `<div class="detail-row"><span class="detail-label">SEMMSL:</span><span class="detail-value">${params.semmsl}</span></div>`;
          if (params.semmns) html += `<div class="detail-row"><span class="detail-label">SEMMNS:</span><span class="detail-value">${params.semmns}</span></div>`;
          if (params.semopm) html += `<div class="detail-row"><span class="detail-label">SEMOPM:</span><span class="detail-value">${params.semopm}</span></div>`;
          if (params.semmni) html += `<div class="detail-row"><span class="detail-label">SEMMNI:</span><span class="detail-value">${params.semmni}</span></div>`;
          if (params.sem) html += `<div class="detail-row" style="grid-column: 1 / -1;"><span class="detail-label">SEM:</span><span class="detail-value">${params.sem}</span></div>`;
          html += '</div></div>';
          
          // VM/Memory Tuning
          html += '<div class="info-card" style="margin-top: 1rem;">';
          html += '<h6>📊 VM ve Bellek Ayarları</h6>';
          html += '<div class="detail-grid">';
          
          if (params.vmswappiness) {
            let swapColor = 'var(--txt)';
            if (params.vmswappiness.includes('Yüksek')) swapColor = '#ef4444';
            else if (params.vmswappiness.includes('Düşük')) swapColor = '#10b981';
            html += `<div class="detail-row"><span class="detail-label">VM Swappiness:</span><span class="detail-value" style="color: ${swapColor}; font-weight: 600;">${params.vmswappiness}</span></div>`;
          }
          
          if (params.transparent_hugepage) {
            let thpColor = 'var(--txt)';
            if (params.transparent_hugepage.includes('never')) thpColor = '#10b981';
            else if (params.transparent_hugepage.includes('always')) thpColor = '#ef4444';
            else if (params.transparent_hugepage.includes('madvise')) thpColor = '#f59e0b';
            html += `<div class="detail-row"><span class="detail-label">Transparent Huge Pages:</span><span class="detail-value" style="color: ${thpColor}; font-weight: 600;">${params.transparent_hugepage}</span></div>`;
          }
          
          html += `<div class="detail-row"><span class="detail-label">Dirty Background Ratio:</span><span class="detail-value">${params.vmdirty_background_ratio || 'N/A'}</span></div>`;
          html += `<div class="detail-row"><span class="detail-label">Dirty Ratio:</span><span class="detail-value">${params.vmdirty_ratio || 'N/A'}</span></div>`;
          html += `<div class="detail-row"><span class="detail-label">Overcommit Memory:</span><span class="detail-value">${params.vm_overcommit_memory || 'N/A'}</span></div>`;
          html += `<div class="detail-row"><span class="detail-label">Overcommit Ratio:</span><span class="detail-value">${params.vm_overcommit_ratio || 'N/A'}</span></div>`;
          html += '</div></div>';
          
          element.innerHTML = html;
        } catch (e) {
          console.error('Kernel params parsing error:', e);
          element.innerHTML = '<pre>' + data + '</pre>';
        }
      }
      
      // Initialize all components on page load
      document.addEventListener('DOMContentLoaded', function() {
        initTheme();
        
        // Render CPU processes
        renderProcessList('cpuProcessList', 'cpu');
        
        // Render RAM processes
        renderProcessList('ramProcessList', 'ram');
        
        // Render disk list
        renderDiskList();
        
        // Render services
        renderServiceList('runningServicesList', false);
        renderServiceList('failedServicesList', true);
        
        // Render network interfaces
        renderNetworkInterfaces();
        
        // Render listening ports
        renderListeningPorts();
        
        // Render kernel parameters
        renderKernelParams();
      });
      
      // Run theme init immediately
      initTheme();
    </script>
  </body>
</html>
"""

# Sonuç ekranı
TEMPLATE_RESULTS = r"""
<!doctype html>
<html lang="tr">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{{ title }}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
      :root {
        --bg: #0f1216; --panel: #171b21; --muted: #9aa5b1; --txt: #eef2f6; --brand: #50b0ff; --accent: #7cf; --ring: rgba(80,176,255,.35);
        --drop: #0f1216; --hover: #212833;
      }
      
      /* Light mode variables */
      [data-theme="light"] {
        --bg: #f8fafc; --panel: #ffffff; --muted: #64748b; --txt: #1e293b; --brand: #3b82f6; --accent: #06b6d4; --ring: rgba(59,130,246,.35);
        --drop: #ffffff; --hover: #f1f5f9;
      }
      
      /* Dark mode variables */
      [data-theme="dark"] {
        --bg: #0f1216; --panel: #171b21; --muted: #9aa5b1; --txt: #eef2f6; --brand: #50b0ff; --accent: #7cf; --ring: rgba(80,176,255,.35);
        --drop: #0f1216; --hover: #212833;
      }
      
      body { 
        padding-top: 20px; 
        background: var(--bg); 
        color: var(--txt);
        font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif;
      }
      
      [data-theme="dark"] body { background: linear-gradient(180deg, #0c0f13, #0f1216); }
      [data-theme="light"] body { background: linear-gradient(180deg, #f1f5f9, #f8fafc); }
      
      .container-lg { background: var(--panel); border-radius: 1rem; padding: 2rem; margin-top: 1rem; border: 1px solid; }
      [data-theme="dark"] .container-lg { border-color: #242b37; }
      [data-theme="light"] .container-lg { border-color: #e2e8f0; }
      
      .card { background: var(--panel); border: 1px solid; }
      [data-theme="dark"] .card { border-color: #243044; }
      [data-theme="light"] .card { border-color: #e2e8f0; }
      
      .form-control, .form-select { background: var(--panel); color: var(--txt); border: 1px solid; }
      [data-theme="dark"] .form-control, .form-select { border-color: #243044; }
      [data-theme="light"] .form-control, .form-select { border-color: #e2e8f0; }
      
      .form-control:focus, .form-select:focus { background: var(--panel); color: var(--txt); border-color: var(--brand); box-shadow: 0 0 0 0.2rem var(--ring); }
      
      .table { color: var(--txt); }
      .table-striped > tbody > tr:nth-of-type(odd) > td { background: var(--hover); }
      
      .code { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; }
      .sticky-th th { position: sticky; top: 0; background: var(--bs-body-bg); z-index: 1; }
      .dt-toolbar { display:flex; gap:12px; align-items:center; margin-bottom: 8px; }
      .dt-info { font-size: .9rem; color: var(--muted); }
      .dt-search { max-width: 260px; }
      .dt-pagesize { width: 140px; }
      .dt-pagination .page-link { cursor: pointer; }
      th.sortable { cursor: pointer; }
      th.sortable .arrows { opacity: .5; font-size: .8em; }
      th.sortable.active .arrows { opacity: 1; }
      .badge-wrap { display:flex; gap:8px; flex-wrap:wrap }
      
      .btn-primary { background: var(--brand); border-color: var(--brand); }
      .btn-primary:hover { background: var(--accent); border-color: var(--accent); }
      .btn-success { background: #10b981; border-color: #10b981; }
      .btn-outline-danger { color: #ef4444; border-color: #ef4444; }
      .btn-outline-danger:hover { background: #ef4444; border-color: #ef4444; }
      .btn-outline-primary { color: var(--brand); border-color: var(--brand); }
      .btn-outline-primary:hover { background: var(--brand); border-color: var(--brand); }
      .btn-outline-secondary { color: var(--muted); border-color: var(--muted); }
      .btn-outline-secondary:hover { background: var(--muted); border-color: var(--muted); }
      
      .alert { border: 1px solid; }
      .alert-success { background: rgba(16, 185, 129, 0.1); border-color: #10b981; color: #10b981; }
      .alert-danger { background: rgba(239, 68, 68, 0.1); border-color: #ef4444; color: #ef4444; }
      .alert-warning { background: rgba(245, 158, 11, 0.1); border-color: #f59e0b; color: #f59e0b; }
      .alert-info { background: rgba(59, 130, 246, 0.1); border-color: #3b82f6; color: #3b82f6; }
      
      .badge { background: var(--hover); color: var(--txt); border: 1px solid; }
      [data-theme="dark"] .badge { border-color: #243044; }
      [data-theme="light"] .badge { border-color: #e2e8f0; }
      
      /* Theme Toggle Button */
      #themeToggle { all: unset; cursor: pointer; padding: 0.5rem; border-radius: 0.5rem; display: flex; align-items: center; justify-content: center; background: var(--hover); border: 1px solid transparent; margin-left: auto; }
      #themeToggle:hover { background: var(--hover); border-color: var(--brand); }
      [data-theme="dark"] #themeToggle:hover { border-color: #50b0ff; }
      [data-theme="light"] #themeToggle:hover { border-color: #3b82f6; }
    </style>
  </head>
  <body>
    <div class="container-lg">
      <div class="d-flex align-items-center mb-3">
        <h1 class="mb-0 me-2">{{ title }}</h1>
        <div style="display: flex; align-items: center; gap: 1rem; margin-left: auto;">
          <button id="themeToggle" title="Dark/Light Mode Toggle">
            <span id="themeIcon" style="font-size: 1.2rem;">🌙</span>
          </button>
        </div>

        <div class="ms-auto d-flex align-items-center gap-2">
          <form method="post" action="{{ url_for('export_merged_csv') }}">
            <input type="hidden" name="sql" value="{{ sql|e }}">
            {% for sid in selected_ids %}<input type="hidden" name="server_id" value="{{ sid }}">{% endfor %}
            <button class="btn btn-success btn-sm">Birleşik CSV</button>
          </form>
          <form method="post" action="{{ url_for('export_zip') }}">
            <input type="hidden" name="sql" value="{{ sql|e }}">
            {% for sid in selected_ids %}<input type="hidden" name="server_id" value="{{ sid }}">{% endfor %}
            <button class="btn btn-outline-primary btn-sm">↧ Hepsini CSV (ZIP)</button>
          </form>
        </div>
      </div>

      <div class="mb-3 d-flex gap-2 flex-wrap align-items-center">
        <a href="/multiquery" class="btn btn-outline-secondary">◀ Geri</a>
        <div class="text-muted">SQL:</div>
        <code class="flex-grow-1">{{ sql }}</code>
      </div>

      <div class="badge-wrap mb-3">
        {% for s in servers %}
          <span class="badge text-bg-light border">{{ s.name }} <small class="text-muted">({{ s.host }}:{{ s.port }}/{{ s.dbname }})</small></span>
        {% endfor %}
      </div>

      {% if errors %}
      <div class="alert alert-warning">
        Bazı sunucularda hata oluştu:
        <ul class="mb-0">{% for e in errors %}<li><strong>{{ e.info.name }}</strong>: {{ e.error }}</li>{% endfor %}</ul>
      </div>
      {% endif %}

      <div class="card shadow-sm">
        <div class="card-header">Birleşik Sonuç Tablosu</div>
        <div class="card-body">
          <div class="dt-toolbar">
            <select class="form-select form-select-sm dt-pagesize">
              <option value="10">10 per page</option><option value="25">25 per page</option><option value="50">50 per page</option><option value="100">100 per page</option>
            </select>
            <input type="search" class="form-control form-control-sm dt-search" placeholder="search..."/>
            <div class="ms-auto dt-info"></div>
          </div>
          <div class="table-responsive">
            <table class="table table-sm table-striped table-hover align-middle dt" id="mergedTable">
              <thead class="table-light sticky-th"><tr>
                {% for col in merged.columns %}<th class="code sortable"><span>{{ col }}</span> <span class="arrows">⇅</span></th>{% endfor %}
              </tr></thead>
              <tbody>
                {% for row in merged.rows %}
                  <tr>{% for col in merged.columns %}<td class="code">{{ (row.get(col, '')|string) }}</td>{% endfor %}</tr>
                {% endfor %}
              </tbody>
            </table>
          </div>
          <nav><ul class="pagination pagination-sm mt-2 dt-pagination"></ul></nav>
        </div>
      </div>
    </div>

    <script>
    document.addEventListener('DOMContentLoaded', function(){
      const tbl = document.getElementById('mergedTable');
      const pageSizeSel = document.querySelector('.dt-pagesize');
      const searchInput = document.querySelector('.dt-search');
      const info = document.querySelector('.dt-info');
      const pager = document.querySelector('.dt-pagination');

      let dataRows = Array.from(tbl.tBodies[0].rows);
      let pageSize = parseInt(pageSizeSel.value, 10) || 10;
      let page = 1, sortIndex = -1, sortDir = 1, query = '';

      function normalize(v){ return (v||'').toString().toLowerCase(); }
      function applyFilter(){ if(!query){ return dataRows; } return dataRows.filter(r => Array.from(r.cells).some(c => normalize(c.textContent).includes(query))); }
      function applySort(rows){
        if(sortIndex < 0){ return rows; }
        return rows.slice().sort((a,b)=>{
          const va=a.cells[sortIndex].textContent.trim(); const vb=b.cells[sortIndex].textContent.trim();
          const na=parseFloat(va.replace(',', '.')); const nb=parseFloat(vb.replace(',', '.'));
          const numRE=/^[-+]?\d*[\.,]?\d*$/; const bothNum=numRE.test(va)&&numRE.test(vb)&&!isNaN(na)&&!isNaN(nb);
          return (bothNum? (na-nb) : va.localeCompare(vb,'tr',{numeric:true,sensitivity:'base'})) * sortDir;
        });
      }
      function paginate(rows){
        const total=rows.length, pages=Math.max(1, Math.ceil(total/pageSize)); if(page>pages) page=pages;
        const start=(page-1)*pageSize, end=start+pageSize; info.textContent=`rows ${total? start+1:0} to ${Math.min(end,total)} of ${total}`;
        const tbody=tbl.tBodies[0]; tbody.innerHTML=''; rows.slice(start,end).forEach(r=>tbody.appendChild(r.cloneNode(true)));
        pager.innerHTML='';
        function add(label,p,dis=false,act=false){ const li=document.createElement('li'); li.className='page-item'+(dis?' disabled':'')+(act?' active':''); const a=document.createElement('a'); a.className='page-link'; a.textContent=label; a.href='#'; a.addEventListener('click',e=>{e.preventDefault(); if(!dis&&!act){page=p; render();}}); li.appendChild(a); pager.appendChild(li);}        
        add('«',1,page===1); add('‹',Math.max(1,page-1),page===1); const maxBtns=5; let s=Math.max(1,page-Math.floor(maxBtns/2)); let e=Math.min(pages,s+maxBtns-1); s=Math.max(1,e-maxBtns+1); for(let i=s;i<=e;i++){ add(String(i),i,false,i===page);} add('›',Math.min(pages,page+1),page===pages); add('»',pages,page===pages);
      }
      function render(){ const filtered=applyFilter(); const sorted=applySort(filtered); paginate(sorted); }
      searchInput.addEventListener('input', function(){ query=this.value.trim().toLowerCase(); page=1; render(); });
      pageSizeSel.addEventListener('change', function(){ pageSize=parseInt(this.value,10)||10; page=1; render(); });
      tbl.querySelectorAll('thead th').forEach(function(th, idx){ th.classList.add('sortable'); th.addEventListener('click', function(){ if(sortIndex===idx){ sortDir=-sortDir; } else { sortIndex=idx; sortDir=1; } tbl.querySelectorAll('thead th').forEach(x=>x.classList.remove('active')); th.classList.add('active'); render(); }); });
      render();
    });

    // Dark Mode Toggle
    function initTheme() {
      const savedTheme = localStorage.getItem('theme') || 'dark';
      const prefersDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
      const theme = savedTheme === 'dark' || (savedTheme === 'auto' && prefersDark) ? 'dark' : 'light';
      
      document.documentElement.setAttribute('data-theme', theme);
      
      const themeIcon = document.getElementById('themeIcon');
      if (themeIcon) {
        themeIcon.textContent = theme === 'dark' ? '🌙' : '☀️';
      }
      
      localStorage.setItem('theme', theme);
    }

    function toggleTheme() {
      const currentTheme = document.documentElement.getAttribute('data-theme');
      const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
      
      document.documentElement.setAttribute('data-theme', newTheme);
      
      const themeIcon = document.getElementById('themeIcon');
      if (themeIcon) {
        themeIcon.textContent = newTheme === 'dark' ? '🌙' : '☀️';
      }
      
      localStorage.setItem('theme', newTheme);
    }

    // Initialize theme on page load
    initTheme();

    // Add click event to theme toggle
    const themeToggle = document.getElementById('themeToggle');
    if (themeToggle) {
      themeToggle.addEventListener('click', toggleTheme);
    }
    });
    </script>
    {{ theme_script|safe }}
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
  </body>
</html>
"""

# -------------------- Yardımcı --------------------
def _in_clause_placeholders(n: int) -> str:
    return ",".join(["?"] * n)

# -------------------- ROUTES --------------------
# Giriş sayfası
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        
        user = authenticate_user(username, password)
        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['full_name'] = user['full_name']
            session['is_admin'] = user['is_admin']
            
            # Last login'i güncelle
            db_execute("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?", (user['id'],))
            
            log_activity(user['id'], user['username'], 'login', f"Başarılı giriş - IP: {request.remote_addr}", 'login')
            flash(f"Hoş geldiniz, {user['full_name']}!", "success")
            return redirect(url_for("landing"))
        else:
            flash("Kullanıcı adı veya şifre hatalı!", "danger")
    
    return render_template_string(TEMPLATE_LOGIN)

# Çıkış
@app.route("/logout")
def logout():
    if 'user_id' in session:
        log_activity(session['user_id'], session['username'], 'logout', f"Çıkış yapıldı - IP: {request.remote_addr}", 'logout')
        session.clear()
        flash("Başarıyla çıkış yaptınız.", "info")
    return redirect(url_for("login"))

# Landing: d1.html
@app.route("/")
@require_auth()
def landing():
    return render_template_string(TEMPLATE_LANDING)

# Multiquery ana ekranı
@app.route("/multiquery")
@require_auth("multiquery")
def multiquery():
    # Manuel eklenen sunucular (servers tablosu)
    manual_servers = db_query("SELECT * FROM servers ORDER BY id DESC")
    
    # Envanter sunucuları boş başlatılır - sadece butona tıklandığında yüklenecek
    inventory_servers = []
    
    return render_template_string(
        TEMPLATE_INDEX,
        title=APP_TITLE,
        servers=manual_servers,
        manual_servers=manual_servers,
        inventory_servers=inventory_servers,
        MAX_ROWS=MAX_ROWS,
        STMT_TIMEOUT_MS=STMT_TIMEOUT_MS,
        theme_script=THEME_SCRIPT,
    )

# Envanter sayfası
@app.route("/envanter")
@require_auth("multiquery")
def envanter():
    # Envanter sayfası ziyaret edildiğini logla
    log_activity(session['user_id'], session['username'], 'envanter_access', 
                'Envanter ana sayfasını ziyaret etti', 'envanter')
    return render_template_string(TEMPLATE_ENVANTER, theme_script=THEME_SCRIPT)

# Envanter sunucularını yükle
@app.route("/load-inventory-servers")
@require_auth("multiquery")
def load_inventory_servers():
    # Envanterdeki sunucular (sunucu_envanteri tablosu) - PostgreSQL varsa
    inventory_servers = []
    try:
        inventory_data = db_query("""
            SELECT hostname, ip, ssh_port, ssh_user, ssh_password, postgresql_status, postgresql_version
            FROM sunucu_envanteri 
            WHERE postgresql_status = 'Var' 
            ORDER BY created_at DESC
        """)
        
        # Envanter sunucularını servers formatına dönüştür
        for inv_server in inventory_data:
            # Şifreyi çöz
            decrypted_password = decrypt_password(inv_server['ssh_password']) if inv_server['ssh_password'] else ''
            
            # PostgreSQL port'unu tespit et (SSH ile bağlanarak)
            postgres_port = 5432  # Varsayılan port
            
            try:
                if decrypted_password:
                    import paramiko
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    ssh.connect(hostname=inv_server['ip'], port=int(inv_server['ssh_port']), 
                               username=inv_server['ssh_user'], password=decrypted_password, timeout=5)
                    
                    # PostgreSQL port'unu tespit et
                    stdin, stdout, stderr = ssh.exec_command("netstat -tlnp 2>/dev/null | grep postgres | head -1 | awk '{print $4}' | cut -d: -f2")
                    port_output = stdout.read().decode().strip()
                    if port_output and port_output.isdigit():
                        postgres_port = int(port_output)
                    else:
                        stdin, stdout, stderr = ssh.exec_command("ss -tlnp 2>/dev/null | grep postgres | head -1 | awk '{print $4}' | cut -d: -f2")
                        port_output = stdout.read().decode().strip()
                        if port_output and port_output.isdigit():
                            postgres_port = int(port_output)
                    
                    ssh.close()
            except Exception as e:
                print(f"Port tespit hatası {inv_server['hostname']}: {e}")
                postgres_port = 5432  # Hata durumunda varsayılan port
            
            # PostgreSQL bağlantı bilgilerini ayarla
            inventory_servers.append({
                'id': f"inv_{inv_server['hostname']}",  # Envanter sunucuları için özel ID
                'name': f"{inv_server['hostname']} (Envanter)",
                'host': inv_server['ip'],
                'port': postgres_port,
                'dbname': 'postgres',
                'username': 'postgres',
                'password': decrypted_password,
                'ssh_port': inv_server['ssh_port'],
                'ssh_user': inv_server['ssh_user'],
                'postgresql_status': inv_server['postgresql_status'],
                'postgresql_version': inv_server['postgresql_version'],
                'is_inventory': True
            })
    except Exception as e:
        print(f"Envanter sunucuları alınırken hata: {e}")
    
    # Manuel sunucuları da al
    manual_servers = db_query("SELECT * FROM servers ORDER BY id DESC")
    
    # Tüm sunucuları birleştir
    all_servers = manual_servers + inventory_servers
    
    return render_template_string(
        TEMPLATE_INDEX,
        title=APP_TITLE,
        servers=all_servers,
        manual_servers=manual_servers,
        inventory_servers=inventory_servers,
        MAX_ROWS=MAX_ROWS,
        STMT_TIMEOUT_MS=STMT_TIMEOUT_MS,
        theme_script=THEME_SCRIPT,
    )

# Healthcheck sayfası
@app.route("/healthcheck")
@require_auth("multiquery")
def healthcheck():
    # Healthcheck sayfası ziyaret edildiğini logla
    log_activity(session['user_id'], session['username'], 'healthcheck_access', 
                'Healthcheck sayfasını ziyaret etti', 'healthcheck')
    
    # Sunucu listesini çek
    servers = db_query("SELECT * FROM sunucu_envanteri ORDER BY hostname")
    
    # Son 50 healthcheck kaydını çek
    history = db_query("""
        SELECT * FROM healthcheck_results 
        ORDER BY created_at DESC 
        LIMIT 50
    """)
    
    return render_template_string(TEMPLATE_HEALTHCHECK, servers=servers, history=history)

# Healthcheck Detay Sayfası
@app.route("/healthcheck/detail/<int:record_id>")
@require_auth("multiquery")
def healthcheck_detail(record_id):
    # Healthcheck detay sayfası ziyaret edildiğini logla
    log_activity(session['user_id'], session['username'], 'healthcheck_detail_access', 
                f'Healthcheck detayını görüntüledi (ID: {record_id})', 'healthcheck')
    
    # Healthcheck kaydını çek
    record = db_query("SELECT * FROM healthcheck_results WHERE id = ?", (record_id,))
    
    if not record:
        flash("Healthcheck kaydı bulunamadı", "danger")
        return redirect(url_for('healthcheck'))
    
    record = record[0]
    
    return render_template_string(TEMPLATE_HEALTHCHECK_DETAIL, record=record)

# Healthcheck API - Run healthcheck on selected servers
@app.route("/api/healthcheck/run", methods=["POST"])
@require_auth("multiquery")
def api_healthcheck_run():
    try:
        print("[DEBUG] ========== API HEALTHCHECK BAŞLADI ==========")
        data = request.get_json()
        print(f"[DEBUG] Request data: {data}")
        server_ids = data.get('server_ids', [])
        print(f"[DEBUG] Server IDs: {server_ids}")
        
        if not server_ids:
            return jsonify({'success': False, 'message': 'Sunucu seçilmedi'}), 400
        
        results = []
        
        # Her sunucu için healthcheck çalıştır
        for server_id in server_ids:
            # Sunucu bilgilerini çek
            server_data = db_query("SELECT * FROM sunucu_envanteri WHERE id = ?", (server_id,))
            
            if not server_data:
                continue
            
            server = server_data[0]
            result = {
                'server_id': server_id,
                'hostname': server['hostname'],
                'ip': server['ip'],
                'status': 'error',
                'error_message': None
            }
            
            ssh = None  # SSH bağlantısını başta None olarak tanımla
            
            try:
                # SSH bağlantısı kur ve bilgileri topla
                if not PARAMIKO_AVAILABLE:
                    result['error_message'] = 'Paramiko kütüphanesi yüklü değil'
                    results.append(result)
                    continue
                
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                
                # Şifreyi çöz
                password = decrypt_password(server['ssh_password']) if server['ssh_password'] else None
                
                if not password:
                    result['error_message'] = 'SSH şifresi bulunamadı'
                    results.append(result)
                    continue
                
                # Bağlan
                ssh.connect(
                    hostname=server['ip'],
                    port=server['ssh_port'],
                    username=server['ssh_user'],
                    password=password,
                    timeout=10
                )
                
                # Sistem bilgilerini topla
                result['status'] = 'success'
                
                # OS Info
                try:
                    stdin, stdout, stderr = ssh.exec_command("cat /etc/os-release | grep PRETTY_NAME | cut -d'\"' -f2")
                    result['os_info'] = stdout.read().decode().strip() or 'N/A'
                except:
                    result['os_info'] = 'N/A'
                
                # CPU Info, Cores ve Sockets - Geliştirilmiş
                try:
                    # CPU model bilgisini al
                    stdin, stdout, stderr = ssh.exec_command("cat /proc/cpuinfo | grep 'model name' | head -1 | cut -d':' -f2 | xargs")
                    cpu_model = stdout.read().decode().strip()
                    
                    # Toplam core sayısını al (logical cores)
                    stdin, stdout, stderr = ssh.exec_command("nproc")
                    total_cores = stdout.read().decode().strip()
                    
                    # Physical core sayısını al
                    stdin, stdout, stderr = ssh.exec_command("grep 'cpu cores' /proc/cpuinfo | head -1 | cut -d':' -f2 | xargs")
                    physical_cores = stdout.read().decode().strip()
                    
                    # Socket sayısını al (fiziksel CPU sayısı)
                    stdin, stdout, stderr = ssh.exec_command("grep 'physical id' /proc/cpuinfo | sort -u | wc -l")
                    sockets = stdout.read().decode().strip()
                    
                    # Hyperthreading kontrolü
                    hyperthreading = "Yes" if (total_cores and physical_cores and int(total_cores) > int(physical_cores)) else "No"
                    
                    # CPU bilgisini birleştir
                    if cpu_model and total_cores:
                        result['cpu_info'] = f"{cpu_model} ({total_cores} cores)"
                        result['cpu_cores'] = f"{total_cores} cores"
                        
                        # Socket ve core detaylarını hazırla
                        cpu_details = []
                        if sockets and int(sockets) > 0:
                            cpu_details.append(f"{sockets} socket(s)")
                        if physical_cores and total_cores:
                            if int(physical_cores) < int(total_cores):
                                cpu_details.append(f"{physical_cores} physical cores")
                                cpu_details.append(f"{total_cores} logical cores")
                            else:
                                cpu_details.append(f"{total_cores} cores")
                        if hyperthreading == "Yes":
                            cpu_details.append("HT enabled")
                        
                        result['cpu_details'] = " | ".join(cpu_details) if cpu_details else f"{total_cores} cores"
                    elif cpu_model:
                        result['cpu_info'] = cpu_model
                        result['cpu_cores'] = 'N/A'
                        result['cpu_details'] = 'N/A'
                    elif total_cores:
                        result['cpu_info'] = f"CPU ({total_cores} cores)"
                        result['cpu_cores'] = f"{total_cores} cores"
                        result['cpu_details'] = f"{total_cores} cores"
                    else:
                        result['cpu_info'] = 'N/A'
                        result['cpu_cores'] = 'N/A'
                        result['cpu_details'] = 'N/A'
                except:
                    result['cpu_info'] = 'N/A'
                    result['cpu_cores'] = 'N/A'
                    result['cpu_details'] = 'N/A'
                
                # RAM Info - Total
                try:
                    stdin, stdout, stderr = ssh.exec_command("free -h | grep 'Mem:' | awk '{print $2}'")
                    result['ram_total'] = stdout.read().decode().strip() or 'N/A'
                except:
                    result['ram_total'] = 'N/A'
                
                # RAM Info - Used
                try:
                    stdin, stdout, stderr = ssh.exec_command("free -h | grep 'Mem:' | awk '{print $3}'")
                    result['ram_used'] = stdout.read().decode().strip() or 'N/A'
                except:
                    result['ram_used'] = 'N/A'
                
                # RAM Info - Free
                try:
                    stdin, stdout, stderr = ssh.exec_command("free -h | grep 'Mem:' | awk '{print $4}'")
                    result['ram_free'] = stdout.read().decode().strip() or 'N/A'
                except:
                    result['ram_free'] = 'N/A'
                
                # Disk Info
                try:
                    stdin, stdout, stderr = ssh.exec_command("df -h | grep -E '^/dev/' | awk '{print $1,$2,$3,$4,$5,$6}'")
                    disk_output = stdout.read().decode().strip()
                    if disk_output:
                        import json
                        disks = []
                        for line in disk_output.split('\n'):
                            parts = line.split()
                            if len(parts) >= 6:
                                disks.append({
                                    'device': parts[0],
                                    'size': parts[1],
                                    'used': parts[2],
                                    'avail': parts[3],
                                    'percent': parts[4],
                                    'mount': parts[5]
                                })
                        result['disks'] = json.dumps(disks)
                    else:
                        result['disks'] = '[]'
                except:
                    result['disks'] = '[]'
                
                # Uptime
                try:
                    stdin, stdout, stderr = ssh.exec_command("uptime -p")
                    result['uptime'] = stdout.read().decode().strip() or 'N/A'
                except:
                    result['uptime'] = 'N/A'
                
                # PostgreSQL Status
                result['postgresql_status'] = 'Yok'
                result['postgresql_version'] = None
                result['postgresql_replication'] = 'N/A'
                
                try:
                    stdin, stdout, stderr = ssh.exec_command("systemctl is-active postgresql 2>/dev/null || systemctl is-active postgresql-* 2>/dev/null | head -1")
                    pg_status = stdout.read().decode().strip()
                    
                    if not pg_status or pg_status == '':
                        stdin, stdout, stderr = ssh.exec_command("ps aux | grep postgres | grep -v grep | wc -l")
                        process_count = stdout.read().decode().strip()
                        if process_count and int(process_count) > 0:
                            pg_status = 'active'
                    
                    if pg_status and ('active' in pg_status.lower() or 'running' in pg_status.lower() or pg_status == 'active'):
                        result['postgresql_status'] = 'Var'
                        
                        # PostgreSQL Version - Multiple methods
                        try:
                            pg_version = None
                            
                            # Method 1: psql --version (doesn't require sudo)
                            stdin, stdout, stderr = ssh.exec_command("psql --version 2>/dev/null")
                            pg_version = stdout.read().decode().strip()
                            
                            if not pg_version or 'PostgreSQL' not in pg_version:
                                # Method 2: pg_config (doesn't require sudo)
                                stdin, stdout, stderr = ssh.exec_command("pg_config --version 2>/dev/null")
                                pg_version = stdout.read().decode().strip()
                            
                            if not pg_version or 'PostgreSQL' not in pg_version:
                                # Method 3: sudo -u postgres psql SELECT version()
                                stdin, stdout, stderr = ssh.exec_command("sudo -n -u postgres psql -t -c 'SELECT version();' 2>/dev/null")
                                pg_version = stdout.read().decode().strip()
                            
                            if not pg_version or 'PostgreSQL' not in pg_version:
                                # Method 4: postgres --version
                                stdin, stdout, stderr = ssh.exec_command("postgres --version 2>/dev/null")
                                pg_version = stdout.read().decode().strip()
                            
                            if not pg_version or 'PostgreSQL' not in pg_version:
                                # Method 5: pg_ctl --version
                                stdin, stdout, stderr = ssh.exec_command("pg_ctl --version 2>/dev/null")
                                pg_version = stdout.read().decode().strip()
                            
                            if pg_version and 'PostgreSQL' in pg_version:
                                import re
                                version_match = re.search(r'PostgreSQL (\d+\.?\d*)', pg_version)
                                if version_match:
                                    result['postgresql_version'] = f"PostgreSQL {version_match.group(1)}"
                                else:
                                    # Fallback: use the full version string
                                    result['postgresql_version'] = pg_version
                            else:
                                result['postgresql_version'] = 'PostgreSQL aktif (versiyon alınamadı)'
                                
                        except Exception as e:
                            print(f"PG Version error: {e}")
                            result['postgresql_version'] = 'PostgreSQL aktif (versiyon alınamadı)'
                        
                        # PostgreSQL Uptime
                        try:
                            stdin, stdout, stderr = ssh.exec_command("sudo -n -u postgres psql -t -c \"SELECT pg_postmaster_start_time() AT TIME ZONE 'UTC' AT TIME ZONE 'Europe/Istanbul';\" 2>/dev/null")
                            pg_start_time = stdout.read().decode().strip()
                            if pg_start_time:
                                result['pg_uptime'] = pg_start_time
                        except:
                            pass
                        
                        # PostgreSQL Toplam Boyut
                        try:
                            # Method 1: Tüm database'lerin toplam boyutu
                            stdin, stdout, stderr = ssh.exec_command("sudo -n -u postgres psql -t -c \"SELECT pg_size_pretty(sum(pg_database_size(datname))) FROM pg_database WHERE datistemplate = false;\" 2>/dev/null")
                            pg_size = stdout.read().decode().strip()
                            
                            if not pg_size:
                                # Method 2: Sadece postgres database boyutu
                                stdin, stdout, stderr = ssh.exec_command("sudo -n -u postgres psql -t -c \"SELECT pg_size_pretty(pg_database_size('postgres'));\" 2>/dev/null")
                                pg_size = stdout.read().decode().strip()
                            
                            if not pg_size:
                                # Method 3: Data directory boyutu
                                stdin, stdout, stderr = ssh.exec_command("sudo -n du -sh /var/lib/postgresql/*/main 2>/dev/null | head -1 | awk '{print $1}'")
                                pg_size = stdout.read().decode().strip()
                            
                            if pg_size:
                                result['pg_total_size'] = pg_size
                        except:
                            pass
                        
                        # Replication Status
                        try:
                            stdin, stdout, stderr = ssh.exec_command("sudo -n -u postgres psql -t -c 'SELECT client_addr FROM pg_stat_replication LIMIT 1;' 2>/dev/null")
                            replication_info = stdout.read().decode().strip()
                            result['postgresql_replication'] = 'Var' if replication_info else 'Yok'
                        except:
                            result['postgresql_replication'] = 'Yok'
                except:
                    pass
                
                # pgBackRest Status
                try:
                    stdin, stdout, stderr = ssh.exec_command("which pgbackrest || find /usr -name pgbackrest 2>/dev/null | head -1")
                    pgbackrest_info = stdout.read().decode().strip()
                    result['pgbackrest_status'] = 'Var' if pgbackrest_info else 'Yok'
                except:
                    result['pgbackrest_status'] = 'Yok'
                
                # Network Info
                try:
                    stdin, stdout, stderr = ssh.exec_command("ip -4 addr show | grep inet | grep -v '127.0.0.1' | awk '{print $2}' | head -3")
                    result['network_info'] = stdout.read().decode().strip().replace('\n', ', ') or 'N/A'
                except:
                    result['network_info'] = 'N/A'
                
                # Load Average
                try:
                    stdin, stdout, stderr = ssh.exec_command("uptime | awk -F'load average:' '{print $2}' | xargs")
                    result['load_average'] = stdout.read().decode().strip() or 'N/A'
                except:
                    result['load_average'] = 'N/A'
                
                # ============ EK DETAYLI BİLGİLER ============
                
                # Kernel Version
                try:
                    stdin, stdout, stderr = ssh.exec_command("uname -r")
                    result['kernel_version'] = stdout.read().decode().strip() or 'N/A'
                except:
                    result['kernel_version'] = 'N/A'
                
                # Architecture
                try:
                    stdin, stdout, stderr = ssh.exec_command("uname -m")
                    result['architecture'] = stdout.read().decode().strip() or 'N/A'
                except:
                    result['architecture'] = 'N/A'
                
                # Last Boot Time
                try:
                    stdin, stdout, stderr = ssh.exec_command("who -b | awk '{print $3, $4}'")
                    result['last_boot'] = stdout.read().decode().strip() or 'N/A'
                except:
                    result['last_boot'] = 'N/A'
                
                # Swap Memory
                try:
                    stdin, stdout, stderr = ssh.exec_command("free -h | grep 'Swap:' | awk '{print \"Total: \" $2 \", Used: \" $3 \", Free: \" $4}'")
                    result['swap_memory'] = stdout.read().decode().strip() or 'N/A'
                except:
                    result['swap_memory'] = 'N/A'
                
                # Memory Detailed Info
                try:
                    stdin, stdout, stderr = ssh.exec_command("free -h | grep 'Mem:' | awk '{print \"Available: \" $7 \", Buffers: \" $6}'")
                    result['memory_detailed'] = stdout.read().decode().strip() or 'N/A'
                except:
                    result['memory_detailed'] = 'N/A'
                
                # Top 5 CPU Processes
                try:
                    stdin, stdout, stderr = ssh.exec_command("ps aux --sort=-%cpu | head -6 | tail -5 | awk '{print $11, $3\"%\"}'")
                    top_cpu = stdout.read().decode().strip()
                    result['top_cpu_processes'] = top_cpu.replace('\n', ' | ') if top_cpu else 'N/A'
                except:
                    result['top_cpu_processes'] = 'N/A'
                
                # Top 5 Memory Processes
                try:
                    stdin, stdout, stderr = ssh.exec_command("ps aux --sort=-%mem | head -6 | tail -5 | awk '{print $11, $4\"%\"}'")
                    top_mem = stdout.read().decode().strip()
                    result['top_memory_processes'] = top_mem.replace('\n', ' | ') if top_mem else 'N/A'
                except:
                    result['top_memory_processes'] = 'N/A'
                
                # Disk I/O Statistics
                try:
                    stdin, stdout, stderr = ssh.exec_command("iostat -d -k 1 2 | tail -n +4 | grep -E '^(sd|nvme|vd)' | head -5")
                    result['disk_io_stats'] = stdout.read().decode().strip() or 'N/A'
                except:
                    result['disk_io_stats'] = 'N/A'
                
                # Disk Performance Test - Basit test (sudo_exec olmadan - daha sonra yapacağız)
                # Bu bölümde sadece placeholder koyuyoruz, asıl test PostgreSQL bölümünden sonra yapılacak
                result['disk_type'] = 'PENDING'
                result['disk_write_speed'] = 'PENDING'
                result['disk_read_speed'] = 'PENDING'
                result['disk_performance_test'] = 'PENDING'
                
                # Network Interfaces
                try:
                    stdin, stdout, stderr = ssh.exec_command("ip -br addr show | grep -v 'lo'")
                    result['network_interfaces'] = stdout.read().decode().strip() or 'N/A'
                except:
                    result['network_interfaces'] = 'N/A'
                
                # DNS Servers
                try:
                    stdin, stdout, stderr = ssh.exec_command("cat /etc/resolv.conf | grep nameserver | awk '{print $2}'")
                    dns = stdout.read().decode().strip()
                    result['dns_servers'] = dns.replace('\n', ', ') if dns else 'N/A'
                except:
                    result['dns_servers'] = 'N/A'
                
                # Timezone
                try:
                    stdin, stdout, stderr = ssh.exec_command("timedatectl | grep 'Time zone' | awk '{print $3}'")
                    result['timezone'] = stdout.read().decode().strip() or 'N/A'
                except:
                    result['timezone'] = 'N/A'
                
                # System Services (important ones)
                try:
                    stdin, stdout, stderr = ssh.exec_command("systemctl list-units --type=service --state=running | grep -E 'ssh|cron|rsyslog|network' | awk '{print $1}' | head -10")
                    services = stdout.read().decode().strip()
                    result['running_services'] = services.replace('\n', ', ') if services else 'N/A'
                except:
                    result['running_services'] = 'N/A'
                
                # Failed Services - Daha detaylı ve güvenilir parsing
                try:
                    # systemctl'den sadece servis isimlerini al (bullet point'leri atla)
                    stdin, stdout, stderr = ssh.exec_command(r"systemctl list-units --type=service --state=failed --no-pager --plain --no-legend 2>/dev/null | awk '{print $1}' | grep -E '\.service$' | head -10")
                    failed = stdout.read().decode().strip()
                    
                    print(f"[DEBUG] Failed services raw output: '{failed}'")
                    
                    if failed:
                        failed_list = []
                        for service_name in failed.split('\n'):
                            service_name = service_name.strip()
                            # Sadece ● veya boş değilse işle
                            if service_name and service_name != '●' and '.service' in service_name:
                                print(f"[DEBUG] Processing failed service: {service_name}")
                                
                                # Her servis için detaylı bilgi al
                                stdin, stdout, stderr = ssh.exec_command(f"systemctl status {service_name} --no-pager --lines=0 2>/dev/null | grep 'Active:' | cut -d':' -f2-")
                                detail = stdout.read().decode().strip()
                                
                                # Servis adı ve kısa açıklama
                                service_info = f"{service_name}"
                                if detail and detail != service_name:
                                    # Active satırından durumu al
                                    service_info += f" ({detail[:150]})"
                                
                                failed_list.append(service_info)
                                print(f"[DEBUG] Added failed service: {service_info}")
                        
                        result['failed_services'] = ' ||| '.join(failed_list) if failed_list else 'None'
                        print(f"[DEBUG] Final failed_services: {result['failed_services']}")
                    else:
                        result['failed_services'] = 'None'
                        print(f"[DEBUG] No failed services found")
                except Exception as e:
                    print(f"[DEBUG] Failed services exception: {e}")
                    result['failed_services'] = 'N/A'
                
                # System Update Status - Hızlı güncelleme kontrolü (repo update YAPMADAN)
                try:
                    # Basit ve hızlı kontrol - sadece mevcut cache'e bakar
                    update_check_script = """
if command -v apt-get &>/dev/null; then
    # Debian: Sadece mevcut cache'teki güncellemeleri kontrol et (repo update YOK)
    UPDATES=$(apt list --upgradable 2>/dev/null | grep -c upgradable)
    if [ "$UPDATES" -gt 1 ]; then
        echo "STATUS:WARNING|$((UPDATES-1)) paket güncellemesi bekliyor"
    else
        echo "STATUS:OK|Sistem güncel görünüyor"
    fi
elif command -v yum &>/dev/null; then
    # Red Hat: needs-restarting sadece reboot gerekip gerekmediğini kontrol eder (hızlı)
    if command -v needs-restarting &>/dev/null; then
        needs-restarting -r &>/dev/null
        if [ $? -eq 1 ]; then
            echo "STATUS:WARNING|Sistem yeniden başlatma gerektirebilir"
        else
            echo "STATUS:OK|Sistem güncel görünüyor"
        fi
    else
        echo "STATUS:INFO|Güncelleme durumu kontrol edilemiyor"
    fi
else
    echo "STATUS:INFO|Desteklenmeyen sistem"
fi
"""
                    stdin, stdout, stderr = ssh.exec_command(update_check_script)
                    update_output = stdout.read().decode().strip()
                    
                    # Output'u parse et
                    if 'STATUS:OK' in update_output:
                        result['system_update_status'] = 'up-to-date'
                        result['system_update_message'] = update_output.split('STATUS:OK|')[1] if '|' in update_output else 'Sistem güncel'
                    elif 'STATUS:WARNING' in update_output:
                        result['system_update_status'] = 'updates-available'
                        result['system_update_message'] = update_output.split('STATUS:WARNING|')[1] if '|' in update_output else 'Güncellemeler mevcut'
                    else:
                        result['system_update_status'] = 'info'
                        result['system_update_message'] = update_output.split('STATUS:INFO|')[1] if 'STATUS:INFO' in update_output else 'Durum bilinmiyor'
                except:
                    result['system_update_status'] = 'N/A'
                    result['system_update_message'] = 'Kontrol yapılamadı'
                
                # Open Ports
                try:
                    stdin, stdout, stderr = ssh.exec_command("ss -tuln | grep LISTEN | awk '{print $5}' | cut -d':' -f2 | sort -n | uniq | head -20")
                    ports = stdout.read().decode().strip()
                    result['listening_ports'] = ports.replace('\n', ', ') if ports else 'N/A'
                except:
                    result['listening_ports'] = 'N/A'
                
                # Total Connections
                try:
                    stdin, stdout, stderr = ssh.exec_command("ss -s | grep 'TCP:' | awk '{print $2}'")
                    result['total_connections'] = stdout.read().decode().strip() or 'N/A'
                except:
                    result['total_connections'] = 'N/A'
                
                # ============ KERNEL PARAMETRELERİ (PostgreSQL için önemli) ============
                # Shared Memory Parameters
                try:
                    kernel_params = {}
                    
                    # SHMMAX - Maximum shared memory segment size
                    stdin, stdout, stderr = ssh.exec_command("sysctl -n kernel.shmmax 2>/dev/null", timeout=3)
                    shmmax = stdout.read().decode().strip()
                    if shmmax:
                        # Bytes'ı GB'ye çevir
                        shmmax_gb = int(shmmax) / (1024**3) if shmmax.isdigit() else 0
                        kernel_params['shmmax'] = f"{shmmax} bytes ({shmmax_gb:.2f} GB)"
                    else:
                        kernel_params['shmmax'] = 'N/A'
                    
                    # SHMALL - Total amount of shared memory available
                    stdin, stdout, stderr = ssh.exec_command("sysctl -n kernel.shmall 2>/dev/null", timeout=3)
                    shmall = stdout.read().decode().strip()
                    if shmall:
                        # Pages'i GB'ye çevir (4KB page size varsayımı)
                        shmall_gb = (int(shmall) * 4096) / (1024**3) if shmall.isdigit() else 0
                        kernel_params['shmall'] = f"{shmall} pages ({shmall_gb:.2f} GB)"
                    else:
                        kernel_params['shmall'] = 'N/A'
                    
                    # SHMMNI - Maximum number of shared memory segments
                    stdin, stdout, stderr = ssh.exec_command("sysctl -n kernel.shmmni 2>/dev/null", timeout=3)
                    kernel_params['shmmni'] = stdout.read().decode().strip() or 'N/A'
                    
                    # Semaphore Parameters (SEMMSL, SEMMNS, SEMOPM, SEMMNI)
                    stdin, stdout, stderr = ssh.exec_command("sysctl -n kernel.sem 2>/dev/null", timeout=3)
                    sem_params = stdout.read().decode().strip()
                    if sem_params:
                        parts = sem_params.split()
                        if len(parts) >= 4:
                            kernel_params['semmsl'] = f"{parts[0]} (max semaphores per array)"
                            kernel_params['semmns'] = f"{parts[1]} (max semaphores system wide)"
                            kernel_params['semopm'] = f"{parts[2]} (max ops per semop call)"
                            kernel_params['semmni'] = f"{parts[3]} (max semaphore arrays)"
                        else:
                            kernel_params['sem'] = sem_params
                    else:
                        kernel_params['sem'] = 'N/A'
                    
                    # VM Dirty Parameters (Write performance için önemli)
                    stdin, stdout, stderr = ssh.exec_command("sysctl -n vm.dirty_background_ratio 2>/dev/null", timeout=3)
                    kernel_params['vmdirty_background_ratio'] = stdout.read().decode().strip() or 'N/A'
                    
                    stdin, stdout, stderr = ssh.exec_command("sysctl -n vm.dirty_ratio 2>/dev/null", timeout=3)
                    kernel_params['vmdirty_ratio'] = stdout.read().decode().strip() or 'N/A'
                    
                    stdin, stdout, stderr = ssh.exec_command("sysctl -n vm.dirty_background_bytes 2>/dev/null", timeout=3)
                    dirty_bg_bytes = stdout.read().decode().strip()
                    if dirty_bg_bytes and dirty_bg_bytes != '0':
                        dirty_bg_mb = int(dirty_bg_bytes) / (1024**2) if dirty_bg_bytes.isdigit() else 0
                        kernel_params['vmdirty_background_bytes'] = f"{dirty_bg_bytes} bytes ({dirty_bg_mb:.2f} MB)"
                    else:
                        kernel_params['vmdirty_background_bytes'] = '0 (disabled)'
                    
                    stdin, stdout, stderr = ssh.exec_command("sysctl -n vm.dirty_bytes 2>/dev/null", timeout=3)
                    dirty_bytes = stdout.read().decode().strip()
                    if dirty_bytes and dirty_bytes != '0':
                        dirty_mb = int(dirty_bytes) / (1024**2) if dirty_bytes.isdigit() else 0
                        kernel_params['vmdirty_bytes'] = f"{dirty_bytes} bytes ({dirty_mb:.2f} MB)"
                    else:
                        kernel_params['vmdirty_bytes'] = '0 (disabled)'
                    
                    # VM Swappiness
                    stdin, stdout, stderr = ssh.exec_command("sysctl -n vm.swappiness 2>/dev/null", timeout=3)
                    swappiness = stdout.read().decode().strip()
                    kernel_params['vmswappiness'] = swappiness if swappiness else 'N/A'
                    if swappiness and swappiness.isdigit():
                        swap_val = int(swappiness)
                        if swap_val > 60:
                            kernel_params['vmswappiness'] += ' (Yüksek - Disk I/O artabilir)'
                        elif swap_val < 10:
                            kernel_params['vmswappiness'] += ' (Düşük - PostgreSQL için iyi)'
                        else:
                            kernel_params['vmswappiness'] += ' (Normal)'
                    
                    # Kernel Scheduler Autogroup
                    stdin, stdout, stderr = ssh.exec_command("sysctl -n kernel.sched_autogroup_enabled 2>/dev/null", timeout=3)
                    kernel_params['kernelsched_autogroup_enabled'] = stdout.read().decode().strip() or 'N/A'
                    
                    # CPU Scaling Governor
                    stdin, stdout, stderr = ssh.exec_command("cat /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor 2>/dev/null | sort | uniq -c", timeout=3)
                    scaling_gov = stdout.read().decode().strip()
                    if scaling_gov:
                        kernel_params['scaling_governor'] = scaling_gov.replace('\n', ', ')
                    else:
                        kernel_params['scaling_governor'] = 'N/A'
                    
                    # Transparent Huge Pages (PostgreSQL için önemli - kapalı olmalı)
                    stdin, stdout, stderr = ssh.exec_command("cat /sys/kernel/mm/transparent_hugepage/enabled 2>/dev/null", timeout=3)
                    thp = stdout.read().decode().strip()
                    if thp:
                        # [always] madvise never formatında olabilir
                        if '[never]' in thp:
                            kernel_params['transparent_hugepage'] = 'never (PostgreSQL için iyi)'
                        elif '[always]' in thp:
                            kernel_params['transparent_hugepage'] = 'always (PostgreSQL için önerilmez!)'
                        elif '[madvise]' in thp:
                            kernel_params['transparent_hugepage'] = 'madvise (PostgreSQL için kabul edilebilir)'
                        else:
                            kernel_params['transparent_hugepage'] = thp
                    else:
                        kernel_params['transparent_hugepage'] = 'N/A'
                    
                    # Overcommit Memory
                    stdin, stdout, stderr = ssh.exec_command("sysctl -n vm.overcommit_memory 2>/dev/null", timeout=3)
                    overcommit = stdout.read().decode().strip()
                    if overcommit:
                        if overcommit == '0':
                            kernel_params['vm_overcommit_memory'] = '0 (Heuristic - varsayılan)'
                        elif overcommit == '1':
                            kernel_params['vm_overcommit_memory'] = '1 (Always overcommit)'
                        elif overcommit == '2':
                            kernel_params['vm_overcommit_memory'] = '2 (Never overcommit - PostgreSQL için güvenli)'
                        else:
                            kernel_params['vm_overcommit_memory'] = overcommit
                    else:
                        kernel_params['vm_overcommit_memory'] = 'N/A'
                    
                    # Overcommit Ratio
                    stdin, stdout, stderr = ssh.exec_command("sysctl -n vm.overcommit_ratio 2>/dev/null", timeout=3)
                    kernel_params['vm_overcommit_ratio'] = stdout.read().decode().strip() or 'N/A'
                    
                    # Tüm parametreleri JSON formatında sakla
                    import json
                    result['kernel_params'] = json.dumps(kernel_params)
                    result['kernel_params_summary'] = f"SHMMAX: {kernel_params.get('shmmax', 'N/A')}, Swappiness: {kernel_params.get('vmswappiness', 'N/A')}, THP: {kernel_params.get('transparent_hugepage', 'N/A')}"
                    
                except Exception as e:
                    print(f"[DEBUG] Kernel parameters exception: {e}")
                    result['kernel_params'] = '{}'
                    result['kernel_params_summary'] = 'N/A'
                
                # ============ POSTGRESQL DETAYLI BİLGİLER ============
                if result.get('postgresql_status') == 'Var':
                    # PostgreSQL bağlantı stringi oluştur (eğer local PostgreSQL varsa)
                    # Çoğu durumda peer authentication ile bağlanabiliriz
                    pg_host = server['ip']
                    pg_port = '5432'
                    
                    # Port bilgisini bul (ss veya netstat ile)
                    try:
                        stdin, stdout, stderr = ssh.exec_command("ss -tlnp 2>/dev/null | grep postgres | awk '{print $4}' | grep -oE '[0-9]+$' | head -1")
                        detected_port = stdout.read().decode().strip()
                        if detected_port:
                            pg_port = detected_port
                    except:
                        pass
                    
                    # Sudo helper function - şifre ile veya şifresiz sudo
                    def sudo_exec(command, use_password=True, timeout_sec=5):
                        """
                        Sudo komutu çalıştırır. Önce şifresiz (-n) dener, 
                        çalışmazsa SSH şifresi ile dener.
                        timeout_sec: Komut için maksimum bekleme süresi (saniye)
                        """
                        try:
                            # Önce şifresiz sudo dene (-n flag) - timeout ile
                            timeout_cmd = f"timeout {timeout_sec} sudo -n {command} 2>&1"
                            stdin, stdout, stderr = ssh.exec_command(timeout_cmd, timeout=timeout_sec + 2)
                            output = stdout.read().decode().strip()
                            error = stderr.read().decode().strip()
                            
                            # Eğer şifre istiyorsa ve use_password=True ise, şifre ile dene
                            if use_password and ('password' in output.lower() or 'password' in error.lower()):
                                # -S flag: stdin'den şifre oku, 2>/dev/null ile sudo mesajlarını gizle
                                # timeout ile çalıştır
                                timeout_cmd = f"timeout {timeout_sec} bash -c \"echo '{password}' | sudo -S {command} 2>/dev/null\""
                                stdin, stdout, stderr = ssh.exec_command(timeout_cmd, timeout=timeout_sec + 2)
                                output = stdout.read().decode().strip()
                                error = stderr.read().decode().strip()
                                
                                # Sudo mesajlarını temizle
                                # "[sudo] password for xxx:" gibi satırları kaldır
                                lines = output.split('\n')
                                cleaned_lines = []
                                for line in lines:
                                    # Sudo password mesajlarını atla
                                    if not ('[sudo]' in line.lower() and 'password' in line.lower()):
                                        cleaned_lines.append(line)
                                output = '\n'.join(cleaned_lines).strip()
                            
                            # Timeout kontrolü
                            if not output or 'timed out' in error.lower():
                                return None, 'timeout'
                            
                            return output, None
                        except Exception as e:
                            return None, str(e)
                    
                    # Sudo yetkisini test et (debug için)
                    sudo_works = False
                    try:
                        test_output, test_error = sudo_exec("-u postgres psql --version", timeout_sec=3)
                        if test_output and 'PostgreSQL' in test_output:
                            sudo_works = True
                            print(f"[DEBUG] Sudo yetkisi çalışıyor: {test_output}")
                        else:
                            print(f"[DEBUG] Sudo yetkisi çalışmıyor. Output: {test_output}, Error: {test_error}")
                    except Exception as e:
                        print(f"[DEBUG] Sudo test hatası: {e}")
                    
                    # PostgreSQL Connection Count
                    try:
                        # Yöntem 1: Sudo ile (en doğru) - şifre ile deneyecek - timeout 3 saniye
                        pg_conn_count, error = sudo_exec("-u postgres psql -t -c 'SELECT count(*) FROM pg_stat_activity;'", timeout_sec=3)
                        
                        print(f"[DEBUG] Connection count output: '{pg_conn_count}', error: '{error}'")
                        
                        # Eğer sudo çalışmazsa veya hata varsa alternatif yöntem
                        if not pg_conn_count or 'error' in str(pg_conn_count).lower() or error:
                            print(f"[DEBUG] Sudo ile bağlantı sayısı alınamadı, alternatif yöntem deneniyor")
                            # Yöntem 2: netstat/ss ile bağlantı sayısı (yaklaşık)
                            stdin, stdout, stderr = ssh.exec_command(f"ss -tn 2>/dev/null | grep ':{pg_port}' | grep ESTAB | wc -l", timeout=3)
                            pg_conn_count = stdout.read().decode().strip()
                            if pg_conn_count:
                                pg_conn_count = f"~{pg_conn_count} (tahmini)"
                        
                        result['pg_connection_count'] = pg_conn_count if pg_conn_count else 'N/A'
                    except Exception as e:
                        print(f"[DEBUG] Connection count exception: {e}")
                        result['pg_connection_count'] = 'N/A'
                    
                    # PostgreSQL Max Connections
                    try:
                        # Yöntem 1: Sudo ile psql (şifre ile) - timeout 3 saniye
                        max_conn, error = sudo_exec("-u postgres psql -t -c 'SHOW max_connections;'", timeout_sec=3)
                        
                        # Yöntem 2: postgresql.conf dosyasından oku
                        if not max_conn or error or not max_conn.replace(' ', '').isdigit():
                            stdin, stdout, stderr = ssh.exec_command("find /etc/postgresql /var/lib/postgresql -name 'postgresql.conf' 2>/dev/null | head -1 | xargs grep -E '^max_connections' | cut -d'=' -f2 | tr -d ' '", timeout=3)
                            conf_max_conn = stdout.read().decode().strip()
                            if conf_max_conn:
                                max_conn = conf_max_conn
                        
                        # Yöntem 3: Varsayılan değer (100)
                        if not max_conn or not max_conn.replace('~', '').strip().isdigit():
                            max_conn = '100 (varsayılan)'
                        
                        result['pg_max_connections'] = max_conn if max_conn else 'N/A'
                    except:
                        result['pg_max_connections'] = 'N/A'
                    
                    # PostgreSQL Databases - İsimler VE Boyutlar (HIZLI)
                    try:
                        print(f"[DEBUG] PostgreSQL database listesi alınıyor (hızlı yöntem)...")
                        
                        # Yöntem 1: Database isimleri ve boyutları (timeout 3s)
                        dbs, error = sudo_exec("-u postgres psql -t -c \"SELECT datname || ' (' || pg_size_pretty(pg_database_size(datname)) || ')' FROM pg_database WHERE datistemplate = false ORDER BY pg_database_size(datname) DESC LIMIT 20;\"", timeout_sec=3)
                        
                        print(f"[DEBUG] Database query output (first 100 chars): '{dbs[:100] if dbs else 'empty'}', error: '{error}'")
                        
                        # Eğer timeout veya hata oluşursa basit liste
                        if not dbs or error == 'timeout' or len(dbs.strip()) < 3:
                            print(f"[DEBUG] Boyutlu liste alınamadı, sadece isimler deneniyor...")
                            # Sadece isimler (daha hızlı)
                            dbs, error = sudo_exec("-u postgres psql -t -c \"SELECT datname FROM pg_database WHERE datistemplate = false LIMIT 50;\"", timeout_sec=2)
                            print(f"[DEBUG] Database names output: '{dbs[:100] if dbs else 'empty'}', error: '{error}'")
                        
                        # Son çare: base directory count
                        if not dbs or error == 'timeout' or len(dbs.strip()) < 2:
                            print(f"[DEBUG] Sudo başarısız, sadece sayı döndürülüyor...")
                            dbs = f"Database isimleri alınamadı (timeout)"
                        
                        result['pg_databases'] = dbs.replace('\n', ', ') if dbs else 'N/A'
                        result['pg_databases_with_sizes'] = dbs if dbs and '(' in dbs else 'N/A'
                        
                        print(f"[DEBUG] Final pg_databases (first 100 chars): '{result['pg_databases'][:100] if result['pg_databases'] else 'empty'}'")
                    except Exception as e:
                        print(f"[DEBUG] Database list exception: {e}")
                        result['pg_databases'] = 'Hata: ' + str(e)
                        result['pg_databases_with_sizes'] = 'N/A'
                    
                    # PostgreSQL Total Database Size
                    try:
                        # Yöntem 1: Sudo ile psql (şifre ile) - timeout 3 saniye
                        total_size, error = sudo_exec("-u postgres psql -t -c \"SELECT pg_size_pretty(sum(pg_database_size(datname))::bigint) FROM pg_database WHERE datistemplate = false;\"", timeout_sec=3)
                        
                        # Yöntem 2: du ile data directory boyutu (yaklaşık)
                        if not total_size or error:
                            stdin, stdout, stderr = ssh.exec_command("du -sh /var/lib/postgresql/*/main 2>/dev/null | awk '{print $1}' | head -1", timeout=3)
                            du_size = stdout.read().decode().strip()
                            if du_size:
                                total_size = f"~{du_size} (tahmini)"
                        
                        result['pg_total_size'] = total_size if total_size else 'N/A'
                    except:
                        result['pg_total_size'] = 'N/A'
                    
                    # PostgreSQL Data Directory
                    try:
                        # Yöntem 1: Sudo ile psql (şifre ile) - timeout 3 saniye
                        data_dir, error = sudo_exec("-u postgres psql -t -c 'SHOW data_directory;'", timeout_sec=3)
                        
                        # Yöntem 2: postgresql.conf dosyasından oku
                        if not data_dir or error:
                            stdin, stdout, stderr = ssh.exec_command("find /etc/postgresql /var/lib/postgresql -name 'postgresql.conf' 2>/dev/null | head -1 | xargs grep -E '^data_directory' | cut -d'=' -f2 | tr -d \"' \"", timeout=3)
                            conf_data_dir = stdout.read().decode().strip()
                            if conf_data_dir:
                                data_dir = conf_data_dir
                        
                        # Yöntem 3: Standart konumları kontrol et
                        if not data_dir or error:
                            stdin, stdout, stderr = ssh.exec_command("ls -d /var/lib/postgresql/*/main 2>/dev/null | head -1", timeout=3)
                            found_dir = stdout.read().decode().strip()
                            if found_dir:
                                data_dir = found_dir
                        
                        result['pg_data_directory'] = data_dir if data_dir else 'N/A'
                    except:
                        result['pg_data_directory'] = 'N/A'
                    
                    # PostgreSQL Port Detection - Geliştirilmiş
                    try:
                        pg_port = None
                        
                        # Method 1: From PostgreSQL (şifre ile) - timeout 3 saniye
                        port, error = sudo_exec("-u postgres psql -t -c 'SHOW port;'", timeout_sec=3)
                        if port and not error and port.strip().isdigit():
                            pg_port = port.strip()
                            print(f"[DEBUG] PostgreSQL port (psql): {pg_port}")
                        
                        # Method 2: From listening ports - netstat ile
                        if not pg_port:
                            stdin, stdout, stderr = ssh.exec_command("sudo netstat -plnt | grep postgres | awk -F' ' '{print $4}' | cut -d: -f2", timeout=3)
                            netstat_port = stdout.read().decode().strip()
                            if netstat_port and netstat_port.isdigit():
                                pg_port = netstat_port
                                print(f"[DEBUG] PostgreSQL port (netstat): {pg_port}")
                        
                        # Method 3: ss komutu ile
                        if not pg_port:
                            stdin, stdout, stderr = ssh.exec_command("ss -tlnp | grep postgres | awk '{print $4}' | cut -d':' -f2 | sort -u | head -1", timeout=3)
                            ss_port = stdout.read().decode().strip()
                            if ss_port and ss_port.isdigit():
                                pg_port = ss_port
                                print(f"[DEBUG] PostgreSQL port (ss): {pg_port}")
                        
                        # Method 4: postgresql.conf dosyasından
                        if not pg_port:
                            stdin, stdout, stderr = ssh.exec_command("find /etc/postgresql /var/lib/postgresql -name 'postgresql.conf' 2>/dev/null | head -1 | xargs grep -E '^port' | cut -d'=' -f2 | tr -d ' '", timeout=3)
                            conf_port = stdout.read().decode().strip()
                            if conf_port and conf_port.isdigit():
                                pg_port = conf_port
                                print(f"[DEBUG] PostgreSQL port (config): {pg_port}")
                        
                        result['pg_port'] = pg_port if pg_port else 'N/A'
                        print(f"[DEBUG] Final PostgreSQL port: {result['pg_port']}")
                        
                    except Exception as e:
                        print(f"[DEBUG] PostgreSQL port detection exception: {e}")
                        result['pg_port'] = 'N/A'
                    
                    # PostgreSQL Config Helper Function
                    def get_pg_config(param_name, default='N/A'):
                        try:
                            # Yöntem 1: Sudo ile psql SHOW (şifre ile) - timeout 3 saniye
                            value, error = sudo_exec(f"-u postgres psql -t -c 'SHOW {param_name};'", timeout_sec=3)
                            
                            # Yöntem 2: postgresql.conf dosyasından oku
                            if not value or error:
                                stdin, stdout, stderr = ssh.exec_command(f"find /etc/postgresql /var/lib/postgresql -name 'postgresql.conf' 2>/dev/null | head -1 | xargs grep -E '^{param_name}' | cut -d'=' -f2 | cut -d'#' -f1 | tr -d \"' \" | xargs", timeout=3)
                                conf_value = stdout.read().decode().strip()
                                if conf_value:
                                    value = conf_value
                            
                            return value if value else default
                        except:
                            return default
                    
                    # PostgreSQL Shared Buffers
                    result['pg_shared_buffers'] = get_pg_config('shared_buffers', '128MB (varsayılan)')
                    
                    # PostgreSQL Work Mem
                    result['pg_work_mem'] = get_pg_config('work_mem', '4MB (varsayılan)')
                    
                    # PostgreSQL Effective Cache Size
                    result['pg_effective_cache_size'] = get_pg_config('effective_cache_size', '4GB (varsayılan)')
                    
                    # PostgreSQL Maintenance Work Mem
                    result['pg_maintenance_work_mem'] = get_pg_config('maintenance_work_mem', '64MB (varsayılan)')
                    
                    # PostgreSQL WAL Level
                    result['pg_wal_level'] = get_pg_config('wal_level', 'replica (varsayılan)')
                    
                    # PostgreSQL Archive Mode
                    result['pg_archive_mode'] = get_pg_config('archive_mode', 'off (varsayılan)')
                    
                    # PostgreSQL Replication Slots
                    try:
                        # Sudo ile psql (şifre ile) - timeout 3 saniye
                        slots, error = sudo_exec("-u postgres psql -t -c 'SELECT slot_name, slot_type, active FROM pg_replication_slots;'", timeout_sec=3)
                        result['pg_replication_slots'] = slots.replace('\n', ' | ') if slots and not error else 'None'
                    except:
                        result['pg_replication_slots'] = 'N/A'
                    
                    # PostgreSQL Uptime
                    try:
                        # Yöntem 1: Sudo ile psql (şifre ile) - timeout 3 saniye
                        uptime, error = sudo_exec("-u postgres psql -t -c \"SELECT date_trunc('second', current_timestamp - pg_postmaster_start_time()) as uptime;\"", timeout_sec=3)
                        
                        # Yöntem 2: ps komutu ile postgres process uptime
                        if not uptime or error:
                            stdin, stdout, stderr = ssh.exec_command("ps -eo pid,etime,cmd | grep '[p]ostgres.*main' | head -1 | awk '{print $2}'", timeout=3)
                            ps_uptime = stdout.read().decode().strip()
                            if ps_uptime:
                                uptime = ps_uptime
                        
                        result['pg_uptime'] = uptime if uptime else 'N/A'
                    except:
                        result['pg_uptime'] = 'N/A'
                    
                    # ============ POSTGRESQL BACKUP ARAÇLARI ============
                    # Backup araçlarını kontrol et
                    
                    # pgBackRest - sudo ile çalıştır
                    result['pgbackrest_details'] = 'Yok'
                    try:
                        # Önce kurulu mu kontrol et
                        stdin, stdout, stderr = ssh.exec_command("command -v pgbackrest 2>/dev/null", timeout=3)
                        pgbackrest_path = stdout.read().decode().strip()
                        
                        if pgbackrest_path:
                            result['pgbackrest_status'] = 'Var'
                            
                            # sudo ile pgbackrest info çalıştır (permission sorununu çözer) - timeout 5 saniye
                            pgbackrest_output, error = sudo_exec("pgbackrest info 2>&1", timeout_sec=5)
                            
                            if pgbackrest_output and not error:
                                # Çıktıyı temizle - ilk 15 satır
                                lines = [l.strip() for l in pgbackrest_output.split('\n') if l.strip()][:15]
                                result['pgbackrest_details'] = '\n'.join(lines)
                            else:
                                result['pgbackrest_details'] = f"Kurulu: {pgbackrest_path}\nBilgi alınamadı"
                        else:
                            result['pgbackrest_status'] = 'Yok'
                            result['pgbackrest_details'] = 'Yok'
                    except Exception as e:
                        result['pgbackrest_status'] = 'Yok'
                        result['pgbackrest_details'] = 'N/A'
                    
                    # pg_probackup - sudo ile çalıştır
                    result['pg_probackup_status'] = 'Yok'
                    result['pg_probackup_path'] = 'N/A'
                    result['pg_probackup_details'] = 'Yok'
                    try:
                        stdin, stdout, stderr = ssh.exec_command("command -v pg_probackup 2>/dev/null", timeout=3)
                        pg_probackup_path = stdout.read().decode().strip()
                        
                        if pg_probackup_path:
                            result['pg_probackup_status'] = 'Var'
                            result['pg_probackup_path'] = pg_probackup_path
                            
                            # pg_probackup ile backup dizinlerini listele - timeout 5 saniye
                            probackup_output, error = sudo_exec("pg_probackup show 2>&1", timeout_sec=5)
                            if probackup_output and not error:
                                lines = [l.strip() for l in probackup_output.split('\n') if l.strip()][:10]
                                result['pg_probackup_details'] = '\n'.join(lines)
                            else:
                                result['pg_probackup_details'] = f"Kurulu: {pg_probackup_path}"
                    except:
                        pass
                    
                    # pgBarman - sudo ile çalıştır
                    result['pgbarman_status'] = 'Yok'
                    result['pgbarman_details'] = 'Yok'
                    try:
                        stdin, stdout, stderr = ssh.exec_command("command -v barman 2>/dev/null", timeout=3)
                        barman_path = stdout.read().decode().strip()
                        
                        if barman_path:
                            result['pgbarman_status'] = 'Var'
                            
                            # Barman server listesini al (sudo ile) - timeout 5 saniye
                            barman_output, error = sudo_exec("barman list-server 2>&1", timeout_sec=5)
                            
                            if barman_output and not error:
                                # Barman diagnose ile detaylı bilgi - timeout 5 saniye
                                barman_detail, detail_error = sudo_exec("barman diagnose 2>&1 | grep -A5 'server_name' | head -10", timeout_sec=5)
                                
                                if barman_detail and not detail_error:
                                    result['pgbarman_details'] = f"Path: {barman_path}\n\nServers:\n{barman_output}\n\nDiagnose:\n{barman_detail}"
                                else:
                                    result['pgbarman_details'] = f"Path: {barman_path}\n\nServers:\n{barman_output}"
                            else:
                                result['pgbarman_details'] = f"Path: {barman_path}\nServer listesi alınamadı"
                    except:
                        pass
                    
                    # Backup info - tüm bilgileri birleştir
                    backup_summary = []
                    if result['pgbackrest_status'] == 'Var':
                        backup_summary.append(f"pgBackRest: Kurulu")
                    if result['pg_probackup_status'] == 'Var':
                        backup_summary.append(f"pg_probackup: Kurulu")
                    if result['pgbarman_status'] == 'Var':
                        backup_summary.append(f"pgBarman: Kurulu")
                    
                    result['backup_info'] = ' | '.join(backup_summary) if backup_summary else 'Hiçbir backup aracı bulunamadı'
                    
                    # ============ HIGH AVAILABILITY ARAÇLARI ============
                    
                    # Patroni kontrolü - Geliştirilmiş
                    result['patroni_status'] = 'Yok'
                    result['patroni_details'] = 'N/A'
                    try:
                        print(f"[DEBUG] Patroni kontrolü başlatılıyor...")
                        
                        # Yöntem 1: Patroni komutunun varlığını kontrol et
                        stdin, stdout, stderr = ssh.exec_command("command -v patroni > /dev/null && echo 'found' || echo 'not_found'", timeout=3)
                        patroni_cmd_check = stdout.read().decode().strip()
                        print(f"[DEBUG] Patroni command check result: '{patroni_cmd_check}'")
                        
                        # Yöntem 1b: Patroni paket kontrolü
                        stdin, stdout, stderr = ssh.exec_command("rpm -q patroni 2>/dev/null || dpkg -l | grep patroni 2>/dev/null | head -1", timeout=3)
                        patroni_package = stdout.read().decode().strip()
                        print(f"[DEBUG] Patroni package check result: '{patroni_package}'")
                        
                        # Yöntem 2: Patroni process kontrolü (daha geniş arama)
                        stdin, stdout, stderr = ssh.exec_command("ps aux | grep -v grep | grep -i patroni | wc -l", timeout=3)
                        patroni_process = stdout.read().decode().strip()
                        print(f"[DEBUG] Patroni process count: '{patroni_process}'")
                        
                        # Yöntem 2b: Patroni process detayları
                        stdin, stdout, stderr = ssh.exec_command("ps aux | grep -v grep | grep -i patroni | head -3", timeout=3)
                        patroni_process_details = stdout.read().decode().strip()
                        print(f"[DEBUG] Patroni process details: '{patroni_process_details}'")
                        
                        # Yöntem 3: patronictl komutunun varlığını kontrol et
                        stdin, stdout, stderr = ssh.exec_command("command -v patronictl > /dev/null && echo 'found' || echo 'not_found'", timeout=3)
                        patronictl_cmd_check = stdout.read().decode().strip()
                        print(f"[DEBUG] Patronictl command check result: '{patronictl_cmd_check}'")
                        
                        # Yöntem 4: Patroni config dosyası arama (daha geniş)
                        stdin, stdout, stderr = ssh.exec_command("find /etc /opt /usr/local -name '*patroni*' -type f 2>/dev/null | head -5", timeout=3)
                        patroni_files = stdout.read().decode().strip()
                        print(f"[DEBUG] Patroni files found: '{patroni_files}'")
                        
                        print(f"[DEBUG] Patroni command check: {patroni_cmd_check}, Process count: {patroni_process}, Patronictl check: {patronictl_cmd_check}, Package: {patroni_package}, Files: {patroni_files}")
                        
                        if (patroni_cmd_check == 'found' or patronictl_cmd_check == 'found' or 
                            patroni_package or patroni_files or
                            (patroni_process and int(patroni_process) > 0)):
                            result['patroni_status'] = 'Var'
                            print(f"[DEBUG] Patroni bulundu, detaylar alınıyor...")
                            
                            # Patroni config dosyasını bul (birden fazla konum)
                            patroni_config = None
                            config_paths = [
                                "/etc/patroni/patroni.yml",
                                "/etc/patroni.yml", 
                                "/opt/patroni/etc/patroni.yml",
                                "/usr/local/etc/patroni.yml"
                            ]
                            
                            for config_path in config_paths:
                                stdin, stdout, stderr = ssh.exec_command(f"test -f {config_path} && echo 'exists' || echo 'not_exists'", timeout=2)
                                if stdout.read().decode().strip() == 'exists':
                                    patroni_config = config_path
                                    break
                            
                            # Eğer standart konumlarda yoksa find ile ara
                            if not patroni_config:
                                stdin, stdout, stderr = ssh.exec_command("find /etc /opt /usr/local -name 'patroni.yml' 2>/dev/null | head -1", timeout=3)
                                patroni_config = stdout.read().decode().strip()
                            
                            print(f"[DEBUG] Patroni config bulundu: {patroni_config}")
                            
                            if patroni_config:
                                # Config'den scope değerini al
                                stdin, stdout, stderr = ssh.exec_command(f"grep 'scope:' {patroni_config} | awk '{{print $2}}' | head -1", timeout=3)
                                scope = stdout.read().decode().strip()
                                
                                # Config'den diğer önemli bilgileri al
                                stdin, stdout, stderr = ssh.exec_command(f"grep -E '^name:|^restapi:|^postgresql:' {patroni_config} | head -5", timeout=3)
                                config_info = stdout.read().decode().strip()
                                
                                details = f"Config: {patroni_config}\n"
                                if scope:
                                    details += f"Scope: {scope}\n"
                                if config_info:
                                    details += f"Config Info:\n{config_info}\n"
                                if patroni_package:
                                    details += f"Package: {patroni_package}\n"
                                if patroni_files:
                                    details += f"Files Found: {patroni_files}\n"
                                if patroni_process_details:
                                    details += f"Process Details:\n{patroni_process_details}\n"
                                
                                # patronictl list komutu ile cluster bilgisi al
                                if patronictl_cmd_check == 'found' and scope:
                                    print(f"[DEBUG] patronictl list komutu çalıştırılıyor...")
                                    patronictl_output, error = sudo_exec(f"patronictl -c {patroni_config} list", timeout_sec=8)
                                    if patronictl_output and not error:
                                        details += f"\nCluster Status:\n{patronictl_output}"
                                        print(f"[DEBUG] patronictl output alındı: {len(patronictl_output)} karakter")
                                    else:
                                        details += f"\nCluster Status: Alınamadı (Error: {error})"
                                        print(f"[DEBUG] patronictl hata: {error}")
                                
                                # Patroni service durumu
                                stdin, stdout, stderr = ssh.exec_command("systemctl is-active patroni 2>/dev/null || echo 'inactive'", timeout=3)
                                service_status = stdout.read().decode().strip()
                                if service_status != 'inactive':
                                    details += f"\nService Status: {service_status}"
                                
                                result['patroni_details'] = details
                            else:
                                result['patroni_details'] = "Patroni bulundu ancak config dosyası bulunamadı"
                        else:
                            result['patroni_status'] = 'Yok'
                            result['patroni_details'] = f"Patroni bulunamadı.\nDebug Info:\n- Command: {patroni_cmd_check}\n- Process: {patroni_process}\n- Patronictl: {patronictl_cmd_check}\n- Package: {patroni_package}\n- Files: {patroni_files}"
                            print(f"[DEBUG] Patroni bulunamadı - Command: {patroni_cmd_check}, Process: {patroni_process}, Package: {patroni_package}")
                    except Exception as e:
                        print(f"[DEBUG] Patroni check exception: {e}")
                        result['patroni_status'] = 'Yok'
                        result['patroni_details'] = 'N/A'
                    
                    # Repmgr kontrolü - Geliştirilmiş
                    result['repmgr_status'] = 'Yok'
                    result['repmgr_details'] = 'N/A'
                    try:
                        print(f"[DEBUG] Repmgr kontrolü başlatılıyor...")
                        
                        # Yöntem 1: repmgr komutunun varlığını kontrol et
                        stdin, stdout, stderr = ssh.exec_command("command -v repmgr > /dev/null && echo 'found' || echo 'not_found'", timeout=3)
                        repmgr_cmd_check = stdout.read().decode().strip()
                        print(f"[DEBUG] Repmgr command check result: '{repmgr_cmd_check}'")
                        
                        # Yöntem 1b: repmgr paket kontrolü
                        stdin, stdout, stderr = ssh.exec_command("rpm -q repmgr 2>/dev/null || dpkg -l | grep repmgr 2>/dev/null | head -1", timeout=3)
                        repmgr_package = stdout.read().decode().strip()
                        print(f"[DEBUG] Repmgr package check result: '{repmgr_package}'")
                        
                        # Yöntem 2: repmgr process kontrolü (daha geniş arama)
                        stdin, stdout, stderr = ssh.exec_command("ps aux | grep -v grep | grep -i repmgr | wc -l", timeout=3)
                        repmgr_process = stdout.read().decode().strip()
                        print(f"[DEBUG] Repmgr process count: '{repmgr_process}'")
                        
                        # Yöntem 2b: repmgr process detayları
                        stdin, stdout, stderr = ssh.exec_command("ps aux | grep -v grep | grep -i repmgr | head -3", timeout=3)
                        repmgr_process_details = stdout.read().decode().strip()
                        print(f"[DEBUG] Repmgr process details: '{repmgr_process_details}'")
                        
                        # Yöntem 3: repmgr dosya arama
                        stdin, stdout, stderr = ssh.exec_command("find /etc /opt /usr/local -name '*repmgr*' -type f 2>/dev/null | head -5", timeout=3)
                        repmgr_files = stdout.read().decode().strip()
                        print(f"[DEBUG] Repmgr files found: '{repmgr_files}'")
                        
                        print(f"[DEBUG] Repmgr command check: {repmgr_cmd_check}, Process count: {repmgr_process}, Package: {repmgr_package}, Files: {repmgr_files}")
                        
                        if (repmgr_cmd_check == 'found' or repmgr_package or repmgr_files or 
                            (repmgr_process and int(repmgr_process) > 0)):
                            result['repmgr_status'] = 'Var'
                            print(f"[DEBUG] Repmgr bulundu, detaylar alınıyor...")
                            
                            # Repmgr config dosyasını bul (birden fazla konum)
                            repmgr_conf = None
                            config_paths = [
                                "/etc/repmgr.conf",
                                "/etc/postgresql/*/repmgr.conf",
                                "/var/lib/postgresql/*/repmgr.conf",
                                "/opt/repmgr/repmgr.conf"
                            ]
                            
                            for config_path in config_paths:
                                stdin, stdout, stderr = ssh.exec_command(f"find {config_path} 2>/dev/null | head -1", timeout=3)
                                found_config = stdout.read().decode().strip()
                                if found_config:
                                    repmgr_conf = found_config
                                    break
                            
                            # Eğer standart konumlarda yoksa find ile ara
                            if not repmgr_conf:
                                stdin, stdout, stderr = ssh.exec_command("find /etc /var/lib/postgresql /opt -name 'repmgr.conf' 2>/dev/null | head -1", timeout=3)
                                repmgr_conf = stdout.read().decode().strip()
                            
                            # Repmgr binary dosyasını bul
                            stdin, stdout, stderr = ssh.exec_command("which repmgr || find /usr /opt -name 'repmgr' -type f 2>/dev/null | head -1", timeout=3)
                            repmgr_bin = stdout.read().decode().strip()
                            
                            print(f"[DEBUG] Repmgr config: {repmgr_conf}, Binary: {repmgr_bin}")
                            
                            if repmgr_conf and repmgr_bin:
                                details = f"Config: {repmgr_conf}\nBinary: {repmgr_bin}\n"
                                if repmgr_package:
                                    details += f"Package: {repmgr_package}\n"
                                if repmgr_files:
                                    details += f"Files Found: {repmgr_files}\n"
                                if repmgr_process_details:
                                    details += f"Process Details:\n{repmgr_process_details}\n"
                                
                                # Config'den önemli bilgileri al
                                stdin, stdout, stderr = ssh.exec_command(f"grep -E '^cluster=|^node=|^conninfo=' {repmgr_conf} | head -5", timeout=3)
                                config_info = stdout.read().decode().strip()
                                if config_info:
                                    details += f"Config Info:\n{config_info}\n"
                                
                                # repmgr cluster show komutu çalıştır
                                print(f"[DEBUG] repmgr cluster show komutu çalıştırılıyor...")
                                repmgr_output, error = sudo_exec(f"{repmgr_bin} -f {repmgr_conf} cluster show", timeout_sec=8)
                                
                                if repmgr_output and not error:
                                    details += f"\nCluster Status:\n{repmgr_output}"
                                    print(f"[DEBUG] repmgr cluster show output alındı: {len(repmgr_output)} karakter")
                                else:
                                    details += f"\nCluster Status: Alınamadı (Error: {error})"
                                    print(f"[DEBUG] repmgr cluster show hata: {error}")
                                
                                # repmgr node status komutu
                                print(f"[DEBUG] repmgr node status komutu çalıştırılıyor...")
                                node_output, error = sudo_exec(f"{repmgr_bin} -f {repmgr_conf} node status", timeout_sec=5)
                                if node_output and not error:
                                    details += f"\nNode Status:\n{node_output}"
                                    print(f"[DEBUG] repmgr node status output alındı")
                                
                                result['repmgr_details'] = details
                            else:
                                result['repmgr_details'] = "Repmgr bulundu ancak config veya binary bulunamadı"
                        else:
                            result['repmgr_status'] = 'Yok'
                            result['repmgr_details'] = f"Repmgr bulunamadı.\nDebug Info:\n- Command: {repmgr_cmd_check}\n- Process: {repmgr_process}\n- Package: {repmgr_package}\n- Files: {repmgr_files}"
                            print(f"[DEBUG] Repmgr bulunamadı - Command: {repmgr_cmd_check}, Process: {repmgr_process}, Package: {repmgr_package}")
                    except Exception as e:
                        print(f"[DEBUG] Repmgr check exception: {e}")
                        result['repmgr_status'] = 'Yok'
                        result['repmgr_details'] = 'N/A'
                    
                    # PAF (Pacemaker) kontrolü - Geliştirilmiş
                    result['paf_status'] = 'Yok'
                    result['paf_details'] = 'N/A'
                    try:
                        print(f"[DEBUG] PAF/Pacemaker kontrolü başlatılıyor...")
                        
                        # Yöntem 1: Pacemaker komutunun varlığını kontrol et
                        stdin, stdout, stderr = ssh.exec_command("command -v pacemaker > /dev/null && echo 'found' || echo 'not_found'", timeout=3)
                        pacemaker_cmd_check = stdout.read().decode().strip()
                        
                        # Yöntem 2: pcs komutunun varlığını kontrol et
                        stdin, stdout, stderr = ssh.exec_command("command -v pcs > /dev/null && echo 'found' || echo 'not_found'", timeout=3)
                        pcs_cmd_check = stdout.read().decode().strip()
                        
                        # Yöntem 3: Pacemaker process kontrolü
                        stdin, stdout, stderr = ssh.exec_command("ps aux | grep -v grep | grep pacemaker | wc -l", timeout=3)
                        pacemaker_process = stdout.read().decode().strip()
                        
                        # Yöntem 4: Pacemaker service status
                        stdin, stdout, stderr = ssh.exec_command("systemctl is-active pacemaker 2>/dev/null || echo 'inactive'", timeout=3)
                        pacemaker_status = stdout.read().decode().strip()
                        
                        # Yöntem 5: Corosync service status
                        stdin, stdout, stderr = ssh.exec_command("systemctl is-active corosync 2>/dev/null || echo 'inactive'", timeout=3)
                        corosync_status = stdout.read().decode().strip()
                        
                        print(f"[DEBUG] Pacemaker cmd: {pacemaker_cmd_check}, PCS cmd: {pcs_cmd_check}, Process: {pacemaker_process}, Service: {pacemaker_status}, Corosync: {corosync_status}")
                        
                        if (pacemaker_cmd_check == 'found' or pcs_cmd_check == 'found' or 
                            pacemaker_status == 'active' or corosync_status == 'active' or
                            (pacemaker_process and int(pacemaker_process) > 0)):
                            result['paf_status'] = 'Var'
                            print(f"[DEBUG] PAF/Pacemaker bulundu, detaylar alınıyor...")
                            
                            details = f"Pacemaker Status: {pacemaker_status}\n"
                            details += f"Corosync Status: {corosync_status}\n"
                            if pacemaker_cmd_check == 'found':
                                details += f"Pacemaker Binary: Available\n"
                            if pcs_cmd_check == 'found':
                                details += f"PCS Command: Available\n"
                            
                            # PCS status komutu (en detaylı bilgi)
                            if pcs_cmd_check == 'found':
                                print(f"[DEBUG] pcs status komutu çalıştırılıyor...")
                                pcs_output, error = sudo_exec("pcs status 2>&1", timeout_sec=8)
                                if pcs_output and not error:
                                    details += f"\nCluster Status:\n{pcs_output[:800]}"
                                    print(f"[DEBUG] pcs status output alındı: {len(pcs_output)} karakter")
                                else:
                                    details += f"\nCluster Status: Alınamadı (Error: {error})"
                                    print(f"[DEBUG] pcs status hata: {error}")
                                
                                # PCS resource status
                                print(f"[DEBUG] pcs resource status komutu çalıştırılıyor...")
                                pcs_res_output, error = sudo_exec("pcs resource status 2>&1", timeout_sec=5)
                                if pcs_res_output and not error:
                                    details += f"\nResource Status:\n{pcs_res_output[:400]}"
                                    print(f"[DEBUG] pcs resource status output alındı")
                            
                            # Crm_mon komutu (alternatif)
                            stdin, stdout, stderr = ssh.exec_command("command -v crm_mon > /dev/null && echo 'found' || echo 'not_found'", timeout=3)
                            crm_mon_check = stdout.read().decode().strip()
                            if crm_mon_check == 'found':
                                print(f"[DEBUG] crm_mon komutu çalıştırılıyor...")
                                crm_output, error = sudo_exec("crm_mon -1 2>&1", timeout_sec=5)
                                if crm_output and not error:
                                    details += f"\nCRM Status:\n{crm_output[:400]}"
                                    print(f"[DEBUG] crm_mon output alındı")
                            
                            result['paf_details'] = details
                        else:
                            result['paf_status'] = 'Yok'
                            print(f"[DEBUG] PAF/Pacemaker bulunamadı")
                    except Exception as e:
                        print(f"[DEBUG] PAF check exception: {e}")
                        result['paf_status'] = 'Yok'
                        result['paf_details'] = 'N/A'
                    
                    # Citus kontrolü (Distributed PostgreSQL) - Geliştirilmiş
                    result['citus_status'] = 'Yok'
                    result['citus_details'] = 'N/A'
                    try:
                        print(f"[DEBUG] Citus kontrolü başlatılıyor...")
                        
                        # Yöntem 1: Citus binary kontrolü
                        stdin, stdout, stderr = ssh.exec_command("command -v citus > /dev/null && echo 'found' || echo 'not_found'", timeout=3)
                        citus_cmd_check = stdout.read().decode().strip()
                        
                        # Yöntem 2: Citus extension PostgreSQL içinde var mı kontrol et
                        citus_ext = None
                        citus_ext_error = None
                        if result.get('postgresql_status') == 'Var':
                            print(f"[DEBUG] PostgreSQL aktif, Citus extension kontrol ediliyor...")
                            citus_ext, citus_ext_error = sudo_exec("-u postgres psql -t -c \"SELECT * FROM pg_extension WHERE extname='citus';\"", timeout_sec=5)
                        
                        # Yöntem 3: Citus yapılandırma dosyası kontrolü
                        stdin, stdout, stderr = ssh.exec_command("find /etc -name '*citus*' -type f 2>/dev/null | head -3", timeout=3)
                        citus_configs = stdout.read().decode().strip()
                        
                        # Yöntem 4: Citus paket kontrolü
                        stdin, stdout, stderr = ssh.exec_command("rpm -q citus 2>/dev/null || dpkg -l | grep citus 2>/dev/null | head -1", timeout=3)
                        citus_package = stdout.read().decode().strip()
                        
                        print(f"[DEBUG] Citus cmd: {citus_cmd_check}, Extension: {citus_ext[:50] if citus_ext else 'None'}, Configs: {citus_configs}, Package: {citus_package}")
                        
                        citus_found = False
                        details = ""
                        
                        if citus_cmd_check == 'found':
                            citus_found = True
                            details += "Citus Binary: Available\n"
                        
                        if citus_ext and citus_ext.strip() and not citus_ext_error:
                            citus_found = True
                            details += "Citus Extension: Active\n"
                            print(f"[DEBUG] Citus extension bulundu, detaylar alınıyor...")
                            
                            # Citus worker node listesi
                            citus_nodes, error = sudo_exec("-u postgres psql -t -c \"SELECT * FROM citus_get_active_worker_nodes();\"", timeout_sec=5)
                            if citus_nodes and not error:
                                details += f"Worker Nodes:\n{citus_nodes}\n"
                                print(f"[DEBUG] Citus worker nodes alındı")
                            
                            # Citus coordinator bilgisi
                            citus_coord, error = sudo_exec("-u postgres psql -t -c \"SELECT * FROM citus_get_coordinator_node();\"", timeout_sec=5)
                            if citus_coord and not error:
                                details += f"Coordinator:\n{citus_coord}\n"
                                print(f"[DEBUG] Citus coordinator bilgisi alındı")
                            
                            # Citus cluster bilgisi
                            citus_cluster, error = sudo_exec("-u postgres psql -t -c \"SELECT * FROM citus_get_cluster_health();\"", timeout_sec=5)
                            if citus_cluster and not error:
                                details += f"Cluster Health:\n{citus_cluster}\n"
                                print(f"[DEBUG] Citus cluster health alındı")
                        
                        if citus_configs:
                            citus_found = True
                            details += f"Config Files: {citus_configs}\n"
                        
                        if citus_package:
                            citus_found = True
                            details += f"Package: {citus_package}\n"
                        
                        # Citus yapılandırma dosyası içeriği
                        if citus_configs:
                            config_file = citus_configs.split('\n')[0]
                            stdin, stdout, stderr = ssh.exec_command(f"cat {config_file} 2>/dev/null | head -10", timeout=3)
                            citus_conf_content = stdout.read().decode().strip()
                            if citus_conf_content:
                                details += f"Config Content:\n{citus_conf_content}\n"
                        
                        if citus_found:
                            result['citus_status'] = 'Var'
                            result['citus_details'] = details
                            print(f"[DEBUG] Citus bulundu ve detaylar alındı")
                        else:
                            result['citus_status'] = 'Yok'
                            print(f"[DEBUG] Citus bulunamadı")
                    except Exception as e:
                        print(f"[DEBUG] Citus check exception: {e}")
                        result['citus_status'] = 'Yok'
                        result['citus_details'] = 'N/A'
                    
                    # Streaming Replication Detayları - Geliştirilmiş
                    result['streaming_replication_status'] = 'N/A'
                    result['streaming_replication_details'] = 'N/A'
                    try:
                        print(f"[DEBUG] Streaming Replication kontrolü başlatılıyor...")
                        
                        # Yöntem 1: WAL sender ve receiver process kontrolü
                        stdin, stdout, stderr = ssh.exec_command("ps aux | grep -E 'wal sender|wal receiver' | grep -v grep", timeout=3)
                        wal_processes = stdout.read().decode().strip()
                        
                        # Yöntem 2: pgrep ile process kontrolü
                        stdin, stdout, stderr = ssh.exec_command("pgrep -fl 'wal sender process' | wc -l", timeout=3)
                        wal_sender_count_cmd = stdout.read().decode().strip()
                        
                        stdin, stdout, stderr = ssh.exec_command("pgrep -fl 'wal receiver process' | wc -l", timeout=3)
                        wal_receiver_count_cmd = stdout.read().decode().strip()
                        
                        # Yöntem 3: PostgreSQL replication ayarları kontrolü
                        wal_level = None
                        max_wal_senders = None
                        if result.get('postgresql_status') == 'Var':
                            wal_level, _ = sudo_exec("-u postgres psql -t -c \"SHOW wal_level;\"", timeout_sec=3)
                            max_wal_senders, _ = sudo_exec("-u postgres psql -t -c \"SHOW max_wal_senders;\"", timeout_sec=3)
                        
                        print(f"[DEBUG] WAL processes: {wal_processes[:100] if wal_processes else 'None'}, Sender count: {wal_sender_count_cmd}, Receiver count: {wal_receiver_count_cmd}, WAL Level: {wal_level}, Max WAL Senders: {max_wal_senders}")
                        
                        if wal_processes or (wal_sender_count_cmd and int(wal_sender_count_cmd) > 0) or (wal_receiver_count_cmd and int(wal_receiver_count_cmd) > 0):
                            # WAL sender var mı?
                            wal_sender_count = wal_processes.count('wal sender') if wal_processes else 0
                            wal_receiver_count = wal_processes.count('wal receiver') if wal_processes else 0
                            
                            # pgrep sonuçlarını da ekle
                            if wal_sender_count_cmd and wal_sender_count_cmd.isdigit():
                                wal_sender_count = max(wal_sender_count, int(wal_sender_count_cmd))
                            if wal_receiver_count_cmd and wal_receiver_count_cmd.isdigit():
                                wal_receiver_count = max(wal_receiver_count, int(wal_receiver_count_cmd))
                            
                            details = ""
                            if wal_level:
                                details += f"WAL Level: {wal_level.strip()}\n"
                            if max_wal_senders:
                                details += f"Max WAL Senders: {max_wal_senders.strip()}\n"
                            
                            if wal_sender_count > 0:
                                result['streaming_replication_status'] = f'Master (WAL Sender: {wal_sender_count})'
                                details += f"Role: Master/Primary\nWAL Sender Processes: {wal_sender_count}\n"
                                
                                # pg_stat_replication'dan detaylar al
                                print(f"[DEBUG] pg_stat_replication sorgusu çalıştırılıyor...")
                                repl_details, error = sudo_exec("-u postgres psql -t -c \"SELECT application_name, client_addr, state, sync_state, sent_lsn, write_lsn, flush_lsn, replay_lsn FROM pg_stat_replication;\"", timeout_sec=5)
                                
                                if repl_details and not error:
                                    details += f"\nReplication Status:\n{repl_details}"
                                    print(f"[DEBUG] pg_stat_replication output alındı")
                                else:
                                    details += f"\nReplication Status: Detay alınamadı (Error: {error})"
                                    print(f"[DEBUG] pg_stat_replication hata: {error}")
                                
                                # WAL sender process detayları
                                stdin, stdout, stderr = ssh.exec_command("pgrep -fl 'wal sender process' | head -5", timeout=3)
                                sender_processes = stdout.read().decode().strip()
                                if sender_processes:
                                    details += f"\nWAL Sender Processes:\n{sender_processes}"
                                    
                            elif wal_receiver_count > 0:
                                result['streaming_replication_status'] = 'Replica (WAL Receiver aktif)'
                                details += f"Role: Replica/Standby\nWAL Receiver Process: Active\n"
                                
                                # pg_stat_wal_receiver'dan detaylar al
                                print(f"[DEBUG] pg_stat_wal_receiver sorgusu çalıştırılıyor...")
                                receiver_details, error = sudo_exec("-u postgres psql -t -c \"SELECT pid, status, receive_start_lsn, received_lsn, last_msg_send_time, last_msg_receipt_time FROM pg_stat_wal_receiver;\"", timeout_sec=5)
                                
                                if receiver_details and not error:
                                    details += f"\nReceiver Status:\n{receiver_details}"
                                    print(f"[DEBUG] pg_stat_wal_receiver output alındı")
                                else:
                                    details += f"\nReceiver Status: Detay alınamadı (Error: {error})"
                                    print(f"[DEBUG] pg_stat_wal_receiver hata: {error}")
                                
                                # WAL receiver process detayları
                                stdin, stdout, stderr = ssh.exec_command("pgrep -fl 'wal receiver process'", timeout=3)
                                receiver_processes = stdout.read().decode().strip()
                                if receiver_processes:
                                    details += f"\nWAL Receiver Process:\n{receiver_processes}"
                            
                            result['streaming_replication_details'] = details
                            print(f"[DEBUG] Streaming replication bulundu: {result['streaming_replication_status']}")
                        else:
                            result['streaming_replication_status'] = 'Yok (Standalone)'
                            result['streaming_replication_details'] = 'WAL sender/receiver process bulunamadı'
                            print(f"[DEBUG] Streaming replication bulunamadı")
                            
                    except Exception as e:
                        print(f"[DEBUG] Streaming replication check exception: {e}")
                        result['streaming_replication_status'] = 'N/A'
                        result['streaming_replication_details'] = 'N/A'
                    
                    # HA Tools Summary
                    ha_summary = []
                    if result.get('patroni_status') == 'Var':
                        ha_summary.append('Patroni')
                    if result.get('repmgr_status') == 'Var':
                        ha_summary.append('Repmgr')
                    if result.get('paf_status') == 'Var':
                        ha_summary.append('PAF/Pacemaker')
                    if result.get('citus_status') and 'Var' in result.get('citus_status'):
                        ha_summary.append('Citus')
                    if result.get('streaming_replication_status') and result.get('streaming_replication_status') != 'Yok (Standalone)':
                        ha_summary.append(f"Streaming Replication ({result.get('streaming_replication_status')})")
                    
                    result['ha_tools_summary'] = ' | '.join(ha_summary) if ha_summary else 'HA aracı bulunamadı'
                    
                    # ============ DISK PERFORMANS TESTİ (sudo_exec tanımlandıktan sonra) ============
                    if result['disk_type'] == 'PENDING':
                        try:
                            print(f"[DEBUG] Disk performans testi başlatılıyor...")
                            
                            # Önce disk tipini belirle (hızlı)
                            stdin, stdout, stderr = ssh.exec_command("lsblk -d -n -o NAME,TYPE,ROTA | grep disk | head -1", timeout=3)
                            disk_info = stdout.read().decode().strip()
                            
                            disk_type = 'N/A'
                            if disk_info:
                                parts = disk_info.split()
                                if len(parts) >= 3:
                                    rotation = parts[2]
                                    disk_type = 'SSD' if rotation == '0' else 'HDD'
                                print(f"[DEBUG] Disk info: {disk_info}, Type: {disk_type}")
                            
                            # Hızlı yazma/okuma testi (10MB - çok hızlı) - timeout 10 saniye
                            # Yazma testi
                            write_cmd = "dd if=/dev/zero of=/tmp/speedtest.tmp bs=1M count=10 oflag=direct 2>&1 | tail -1"
                            write_output, write_error = sudo_exec(write_cmd, timeout_sec=10)
                            
                            write_speed = 'N/A'
                            if write_output and not write_error:
                                # dd çıktısından hızı parse et
                                import re
                                speed_match = re.search(r'(\d+\.?\d*)\s*(MB|GB)/s', write_output)
                                if speed_match:
                                    write_speed = f"{speed_match.group(1)} {speed_match.group(2)}/s"
                            
                            # Okuma testi - timeout 10 saniye
                            read_cmd = "dd if=/tmp/speedtest.tmp of=/dev/null bs=1M 2>&1 | tail -1; rm -f /tmp/speedtest.tmp"
                            read_output, read_error = sudo_exec(read_cmd, timeout_sec=10)
                            
                            read_speed = 'N/A'
                            if read_output and not read_error:
                                import re
                                speed_match = re.search(r'(\d+\.?\d*)\s*(MB|GB)/s', read_output)
                                if speed_match:
                                    read_speed = f"{speed_match.group(1)} {speed_match.group(2)}/s"
                            
                            result['disk_type'] = disk_type
                            result['disk_write_speed'] = write_speed
                            result['disk_read_speed'] = read_speed
                            result['disk_performance_test'] = f"Type: {disk_type}\nWrite: {write_output}\nRead: {read_output}"
                            
                            print(f"[DEBUG] Disk performans testi tamamlandı - Type: {disk_type}, Write: {write_speed}, Read: {read_speed}")
                            
                        except Exception as e:
                            print(f"[DEBUG] Disk performans testi exception: {e}")
                            import traceback
                            print(f"[DEBUG] Traceback: {traceback.format_exc()}")
                            result['disk_type'] = 'N/A'
                            result['disk_write_speed'] = 'N/A'
                            result['disk_read_speed'] = 'N/A'
                            result['disk_performance_test'] = f'Test yapılamadı: {str(e)}'
                    
                else:
                    result['pg_connection_count'] = 'N/A'
                    result['pg_max_connections'] = 'N/A'
                    result['pg_databases'] = 'N/A'
                    result['pg_total_size'] = 'N/A'
                    result['pg_data_directory'] = 'N/A'
                    result['pg_port'] = 'N/A'
                    result['pg_shared_buffers'] = 'N/A'
                    result['pg_work_mem'] = 'N/A'
                    result['pg_effective_cache_size'] = 'N/A'
                    result['pg_maintenance_work_mem'] = 'N/A'
                    result['pg_wal_level'] = 'N/A'
                    result['pg_archive_mode'] = 'N/A'
                    result['pg_replication_slots'] = 'N/A'
                    result['pg_uptime'] = 'N/A'
                    
                    # PostgreSQL yoksa HA araçları da yok demektir
                    result['patroni_status'] = 'N/A'
                    result['patroni_details'] = 'N/A'
                    result['repmgr_status'] = 'N/A'
                    result['repmgr_details'] = 'N/A'
                    result['paf_status'] = 'N/A'
                    result['paf_details'] = 'N/A'
                    result['citus_status'] = 'N/A'
                    result['citus_details'] = 'N/A'
                    result['streaming_replication_status'] = 'N/A'
                    result['streaming_replication_details'] = 'N/A'
                    result['ha_tools_summary'] = 'N/A (PostgreSQL yok)'
                
                # SSH bağlantısını kapat
                try:
                    if ssh is not None:
                        # Transport'u da kapat (daemon thread sorununu önler)
                        transport = ssh.get_transport()
                        if transport is not None:
                            transport.close()
                        ssh.close()
                        print(f"[DEBUG] SSH bağlantısı kapatıldı: {result['hostname']}")
                except Exception as e:
                    print(f"[DEBUG] SSH kapatma hatası: {e}")
                
            except Exception as e:
                result['status'] = 'error'
                result['error_message'] = str(e)
                print(f"[ERROR] Healthcheck exception for {result['hostname']}: {e}")
                import traceback
                print(f"[ERROR] Traceback: {traceback.format_exc()}")
                
                # Hata durumunda SSH bağlantısını kapat
                try:
                    if ssh is not None:
                        # Transport'u da kapat (daemon thread sorununu önler)
                        transport = ssh.get_transport()
                        if transport is not None:
                            transport.close()
                        ssh.close()
                        print(f"[DEBUG] SSH bağlantısı kapatıldı (exception handler)")
                except Exception as close_error:
                    print(f"[DEBUG] SSH kapatma hatası (exception handler): {close_error}")
                    pass
                
                # HA araçları için default değerler ekle (hata durumunda)
                result.setdefault('patroni_status', 'N/A')
                result.setdefault('patroni_details', 'N/A')
                result.setdefault('repmgr_status', 'N/A')
                result.setdefault('repmgr_details', 'N/A')
                result.setdefault('paf_status', 'N/A')
                result.setdefault('paf_details', 'N/A')
                result.setdefault('citus_status', 'N/A')
                result.setdefault('citus_details', 'N/A')
                result.setdefault('streaming_replication_status', 'N/A')
                result.setdefault('streaming_replication_details', 'N/A')
                result.setdefault('ha_tools_summary', 'N/A (Hata)')
            
            # Sonucu kaydet - detaylı hata yakalama
            try:
                # INSERT öncesi debug
                print(f"[DEBUG] Saving healthcheck result for {result['hostname']}")
                
                # Önce results'a ekle (database olmasa bile çalışsın)
                results.append(result)
                
                # Database'e kaydet (hata varsa devam edelim)
                db_execute("""
                    INSERT INTO healthcheck_results 
                    (server_id, hostname, ip, status, os_info, cpu_info, cpu_cores, 
                     ram_total, ram_used, ram_free, disks, uptime, postgresql_status, 
                     postgresql_version, postgresql_replication, pgbackrest_status, 
                     network_info, load_average, error_message, checked_by, checked_by_username,
                     system_update_status, system_update_message,
                     pgbackrest_details, pg_probackup_status, pg_probackup_path,
                     pgbarman_status, pgbarman_details, backup_info, pg_probackup_details,
                     disk_type, disk_write_speed, disk_read_speed, disk_performance_test,
                     kernel_version, architecture, last_boot, swap_memory, memory_detailed,
                     top_cpu_processes, top_memory_processes, disk_io_stats, network_interfaces,
                     dns_servers, timezone, running_services, total_connections,
                     pg_connection_count, pg_max_connections, pg_databases, pg_total_size,
                     pg_data_directory, pg_port, pg_shared_buffers, pg_work_mem,
                     pg_effective_cache_size, pg_maintenance_work_mem, pg_wal_level,
                     pg_archive_mode, pg_replication_slots, pg_uptime,
                     failed_services, listening_ports,
                     kernel_params, kernel_params_summary,
                     patroni_status, patroni_details, repmgr_status, repmgr_details,
                     paf_status, paf_details, citus_status, citus_details,
                     streaming_replication_status, streaming_replication_details, ha_tools_summary,
                     cpu_details)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    server_id,
                    result['hostname'],
                    result['ip'],
                    result['status'],
                    result.get('os_info', 'N/A'),
                    result.get('cpu_info', 'N/A'),
                    result.get('cpu_cores', 'N/A'),
                    result.get('ram_total', 'N/A'),
                    result.get('ram_used', 'N/A'),
                    result.get('ram_free', 'N/A'),
                    result.get('disks', '[]'),
                    result.get('uptime', 'N/A'),
                    result.get('postgresql_status', 'Yok'),
                    result.get('postgresql_version', 'N/A'),
                    result.get('postgresql_replication', 'N/A'),
                    result.get('pgbackrest_status', 'Yok'),
                    result.get('network_info', 'N/A'),
                    result.get('load_average', 'N/A'),
                    result.get('error_message', 'N/A'),
                    session['user_id'],
                    session['username'],
                    result.get('system_update_status', 'N/A'),
                    result.get('system_update_message', 'N/A'),
                    result.get('pgbackrest_details', 'N/A'),
                    result.get('pg_probackup_status', 'N/A'),
                    result.get('pg_probackup_path', 'N/A'),
                    result.get('pgbarman_status', 'N/A'),
                    result.get('pgbarman_details', 'N/A'),
                    result.get('backup_info', 'N/A'),
                    result.get('pg_probackup_details', 'N/A'),
                    result.get('disk_type', 'N/A'),
                    result.get('disk_write_speed', 'N/A'),
                    result.get('disk_read_speed', 'N/A'),
                    result.get('disk_performance_test', 'N/A'),
                    result.get('kernel_version', 'N/A'),
                    result.get('architecture', 'N/A'),
                    result.get('last_boot', 'N/A'),
                    result.get('swap_memory', 'N/A'),
                    result.get('memory_detailed', 'N/A'),
                    result.get('top_cpu_processes', 'N/A'),
                    result.get('top_memory_processes', 'N/A'),
                    result.get('disk_io_stats', 'N/A'),
                    result.get('network_interfaces', 'N/A'),
                    result.get('dns_servers', 'N/A'),
                    result.get('timezone', 'N/A'),
                    result.get('running_services', 'N/A'),
                    result.get('total_connections', 'N/A'),
                    result.get('pg_connection_count', 'N/A'),
                    result.get('pg_max_connections', 'N/A'),
                    result.get('pg_databases', 'N/A'),
                    result.get('pg_total_size', 'N/A'),
                    result.get('pg_data_directory', 'N/A'),
                    result.get('pg_port', 'N/A'),
                    result.get('pg_shared_buffers', 'N/A'),
                    result.get('pg_work_mem', 'N/A'),
                    result.get('pg_effective_cache_size', 'N/A'),
                    result.get('pg_maintenance_work_mem', 'N/A'),
                    result.get('pg_wal_level', 'N/A'),
                    result.get('pg_archive_mode', 'N/A'),
                    result.get('pg_replication_slots', 'N/A'),
                    result.get('pg_uptime', 'N/A'),
                    result.get('failed_services', 'N/A'),
                    result.get('listening_ports', 'N/A'),
                    result.get('kernel_params', '{}'),
                    result.get('kernel_params_summary', 'N/A'),
                    result.get('patroni_status', 'N/A'),
                    result.get('patroni_details', 'N/A'),
                    result.get('repmgr_status', 'N/A'),
                    result.get('repmgr_details', 'N/A'),
                    result.get('paf_status', 'N/A'),
                    result.get('paf_details', 'N/A'),
                    result.get('citus_status', 'N/A'),
                    result.get('citus_details', 'N/A'),
                    result.get('streaming_replication_status', 'N/A'),
                    result.get('streaming_replication_details', 'N/A'),
                    result.get('ha_tools_summary', 'N/A'),
                    result.get('cpu_details', 'N/A'),
                ))
                print(f"[DEBUG] Healthcheck sonucu başarıyla kaydedildi")
            except Exception as e:
                print(f"[ERROR] Healthcheck sonucu kaydedilemedi: {e}")
                import traceback
                print(f"[ERROR] Traceback: {traceback.format_exc()}")
                # Database'e kayıt başarısız ama sonuç yine de döndürülsün
        
        # Activity log
        log_activity(session['user_id'], session['username'], 'healthcheck_run', 
                    f"{len(server_ids)} sunucu için healthcheck çalıştırıldı", 'healthcheck')
        
        print(f"[DEBUG] Healthcheck tamamlandı. {len(results)} sonuç dönülüyor.")
        print(f"[DEBUG] ========== API HEALTHCHECK BİTTİ ==========")
        
        return jsonify({'success': True, 'results': results})
        
    except Exception as e:
        print(f"[ERROR] ========== API HEALTHCHECK HATASI ==========")
        print(f"[ERROR] Exception type: {type(e).__name__}")
        print(f"[ERROR] Exception message: {str(e)}")
        import traceback
        print(f"[ERROR] Full traceback:")
        print(traceback.format_exc())
        print(f"[ERROR] ==========================================")
        return jsonify({'success': False, 'message': f'{type(e).__name__}: {str(e)}'}), 500

# Manuel sunucu ekleme sayfası
@app.route("/manuel-sunucu-ekle", methods=["GET", "POST"])
@require_auth("multiquery")
def manuel_sunucu_ekle():
    if request.method == "POST":
        hostname = request.form.get("hostname", "").strip()
        ip = request.form.get("ip", "").strip()
        ssh_port = request.form.get("ssh_port", "22").strip()
        ssh_user = request.form.get("ssh_user", "").strip()
        password = request.form.get("password", "")
        
        if not all([hostname, ip, ssh_user, password]):
            flash("Tüm alanları doldurunuz.", "danger")
            return render_template_string(TEMPLATE_MANUEL_SUNUCU_EKLE, theme_script=THEME_SCRIPT)
        
        # Manuel sunucu ekleme formu gönderildiğini logla
        log_activity(session['user_id'], session['username'], 'form_submit', 
                    f'Manuel sunucu ekleme formu gönderildi - Sunucu: {hostname} ({ip})', 'manuel-sunucu-ekle')
        
        # SSH bağlantısı yaparak sunucu bilgilerini topla
        try:
            server_info = collect_server_info(hostname, ip, ssh_port, ssh_user, password)
            
            # Sunucu tarama işlemi başarılı
            log_activity(session['user_id'], session['username'], 'server_scan', 
                        f'Sunucu tarama başarılı - {hostname} ({ip}) - OS: {server_info.get("os_info", "N/A")} - PostgreSQL: {server_info.get("postgresql_status", "Yok")}', 'manuel-sunucu-ekle')
            
            return render_template_string(TEMPLATE_SUNUCU_BILGILERI, 
                                        server_info=server_info, 
                                        theme_script=THEME_SCRIPT)
        except Exception as e:
            # Sunucu tarama hatası
            log_activity(session['user_id'], session['username'], 'server_scan', 
                        f'Sunucu tarama hatası - {hostname} ({ip}) - Hata: {str(e)}', 'manuel-sunucu-ekle')
            flash(f"Sunucuya bağlanırken hata oluştu: {str(e)}", "danger")
            return render_template_string(TEMPLATE_MANUEL_SUNUCU_EKLE, theme_script=THEME_SCRIPT)
    
    # Manuel sunucu ekleme sayfası ziyaret edildiğini logla
    log_activity(session['user_id'], session['username'], 'manuel_server_add', 
                'Manuel sunucu ekleme sayfasını ziyaret etti', 'manuel-sunucu-ekle')
    return render_template_string(TEMPLATE_MANUEL_SUNUCU_EKLE, theme_script=THEME_SCRIPT)

# Envantere ekleme route'u
@app.route("/envantere-ekle", methods=["POST"])
@require_auth("multiquery")
def envantere_ekle():
    """Sunucu bilgilerini envantere ekle/güncelle"""
    try:
        # Form verilerini al
        server_info = {
            'hostname': request.form.get('hostname', ''),
            'ip': request.form.get('ip', ''),
            'ssh_port': request.form.get('ssh_port', 22),
            'ssh_user': request.form.get('ssh_user', ''),
            'ssh_password': request.form.get('ssh_password', ''),
            'os_info': request.form.get('os_info', 'N/A'),
            'cpu_info': request.form.get('cpu_info', 'N/A'),
            'cpu_cores': request.form.get('cpu_cores', 'N/A'),
            'ram_total': request.form.get('ram_total', 'N/A'),
            'disks': request.form.get('disks', '[]'),
            'uptime': request.form.get('uptime', 'N/A'),
            'postgresql_status': request.form.get('postgresql_status', 'Yok'),
            'postgresql_version': request.form.get('postgresql_version', 'N/A'),
            'postgresql_replication': request.form.get('postgresql_replication', 'N/A'),
            'pgbackrest_status': request.form.get('pgbackrest_status', 'Yok')
        }
        
        # Disks bilgisini parse et
        import json
        try:
            server_info['disks'] = json.loads(server_info['disks'])
        except:
            server_info['disks'] = []
        
        # Sunucu bilgilerini kaydet/güncelle
        success, message = save_sunucu_bilgileri(server_info)
        
        if success:
            # Envantere ekleme başarılı
            log_activity(session['user_id'], session['username'], 'server_add_to_inventory', 
                        f'Sunucu envantere {message} - {server_info.get("hostname", "N/A")} ({server_info.get("ip", "N/A")})', 'envantere-ekle')
            flash(f"Sunucu başarıyla {message}!", "success")
        else:
            # Envantere ekleme başarısız
            log_activity(session['user_id'], session['username'], 'server_add_to_inventory', 
                        f'Envantere ekleme başarısız: {message} - {server_info.get("hostname", "N/A")} ({server_info.get("ip", "N/A")})', 'envantere-ekle')
            flash(f"Sunucu kaydedilemedi: {message}", "danger")
            
    except Exception as e:
        # Envantere ekleme hatası
        log_activity(session['user_id'], session['username'], 'server_add_to_inventory', 
                    f'Envantere ekleme hatası: {str(e)} - {server_info.get("hostname", "N/A")} ({server_info.get("ip", "N/A")})', 'envantere-ekle')
        flash(f"Envantere ekleme hatası: {str(e)}", "danger")
    
    return redirect(url_for("sunuculari_listele"))

# Toplu sunucu ekleme sayfası
@app.route("/toplu-sunucu-ekle", methods=["GET", "POST"])
@require_auth("multiquery")
def toplu_sunucu_ekle():
    if request.method == "POST":
        # Excel dosyasını al
        excel_file = request.files.get("excel_file")
        ssh_user = request.form.get("ssh_user", "").strip()
        ssh_password = request.form.get("ssh_password", "")
        ssh_port = request.form.get("ssh_port", "22").strip()
        
        if not all([excel_file, ssh_user, ssh_password]):
            flash("Tüm alanları doldurunuz.", "danger")
            return render_template_string(TEMPLATE_TOPLU_SUNUCU_EKLE, theme_script=THEME_SCRIPT)
        
        # Toplu sunucu ekleme formu gönderildiğini logla
        log_activity(session['user_id'], session['username'], 'form_submit', 
                    f'Toplu sunucu ekleme formu gönderildi - Excel dosyası: {excel_file.filename}', 'toplu-sunucu-ekle')
        
        try:
            # Excel dosyasını oku
            import pandas as pd
            df = pd.read_excel(excel_file)
            
            # İlk sütundan sunucu isimlerini al
            server_names = df.iloc[:, 0].dropna().astype(str).tolist()
            
            # Debug bilgisi
            print(f"Excel'den okunan sunucu sayısı: {len(server_names)}")
            print(f"Sunucu isimleri: {server_names}")
            
            if not server_names:
                flash("Excel dosyasında sunucu ismi bulunamadı.", "danger")
                return render_template_string(TEMPLATE_TOPLU_SUNUCU_EKLE, theme_script=THEME_SCRIPT)
            
            # Toplu sunucu tarama başladığını logla
            log_activity(session['user_id'], session['username'], 'bulk_server_scan', 
                        f'Toplu sunucu tarama başladı - {len(server_names)} sunucu - Excel: {excel_file.filename}', 'toplu-sunucu-ekle')
            
            # Her sunucu için bilgi topla
            results = []
            for i, hostname in enumerate(server_names, 1):
                try:
                    print(f"Sunucu {i}/{len(server_names)} işleniyor: {hostname}")
                    
                    # Hostname'i IP'ye çevirmeye çalış
                    try:
                        ip = socket.gethostbyname(hostname)
                        print(f"  IP adresi: {ip}")
                    except Exception as e:
                        ip = hostname  # IP çevrilemezse hostname'i kullan
                        print(f"  IP çözülemedi, hostname kullanılıyor: {hostname} (Hata: {e})")
                    
                    # Sunucu bilgilerini topla
                    print(f"  SSH bağlantısı deneniyor...")
                    server_info = collect_server_info(hostname, ip, ssh_port, ssh_user, ssh_password)
                    results.append(server_info)
                    print(f"  ✅ Başarılı: {hostname}")
                    
                except Exception as e:
                    print(f"  ❌ Hata: {hostname} - {str(e)}")
                    # Hata durumunda boş bilgi ekle
                    results.append({
                        'hostname': hostname,
                        'ip': 'Bağlanamadı',
                        'ssh_port': ssh_port,
                        'ssh_user': ssh_user,
                        'ssh_password': ssh_password,  # Şifreyi de ekle
                        'os_info': 'N/A',
                        'cpu_info': 'N/A',
                        'cpu_cores': 'N/A',
                        'ram_total': 'N/A',
                        'disks': [],
                        'uptime': 'N/A',
                        'postgresql_status': 'Yok',
                        'postgresql_version': 'N/A',
                        'postgresql_replication': 'N/A',
                        'pgbackrest_status': 'Yok',
                        'error': str(e)
                    })
            
            # Toplu sunucu tarama tamamlandığını logla
            success_count = sum(1 for r in results if not r.get('error'))
            error_count = len(results) - success_count
            log_activity(session['user_id'], session['username'], 'bulk_server_scan', 
                        f'Toplu sunucu tarama tamamlandı - Başarılı: {success_count}/{len(results)} - Hatalı: {error_count}', 'toplu-sunucu-ekle')
            
            return render_template_string(TEMPLATE_TOPLU_SUNUCU_EKLE, 
                                        results=results, 
                                        theme_script=THEME_SCRIPT)
            
        except Exception as e:
            # Toplu sunucu tarama hatası
            log_activity(session['user_id'], session['username'], 'bulk_server_scan', 
                        f'Toplu sunucu tarama hatası - Excel: {excel_file.filename} - Hata: {str(e)}', 'toplu-sunucu-ekle')
            flash(f"Excel dosyası işlenirken hata oluştu: {str(e)}", "danger")
            return render_template_string(TEMPLATE_TOPLU_SUNUCU_EKLE, theme_script=THEME_SCRIPT)
    
    # Toplu sunucu ekleme sayfası ziyaret edildiğini logla
    log_activity(session['user_id'], session['username'], 'bulk_server_add', 
                'Toplu sunucu ekleme sayfasını ziyaret etti', 'toplu-sunucu-ekle')
    return render_template_string(TEMPLATE_TOPLU_SUNUCU_EKLE, theme_script=THEME_SCRIPT)

# Sunucuları listeleme sayfası
@app.route("/sunuculari-listele")
@require_auth("multiquery")
def sunuculari_listele():
    # Önce duplicate kayıtları temizle
    try:
        cleaned_count = clean_duplicate_servers()
        if cleaned_count > 0:
            flash(f"{cleaned_count} duplicate kayıt temizlendi.", "info")
            # Duplicate temizleme işlemini logla
            log_activity(session['user_id'], session['username'], 'data_cleanup', 
                        f'Duplicate kayıt temizleme - {cleaned_count} kayıt silindi', 'sunuculari-listele')
    except Exception as e:
        print(f"Duplicate temizleme hatası: {e}")
    
    # Veritabanından tüm sunucu bilgilerini al
    try:
        servers = db_query("SELECT * FROM sunucu_envanteri ORDER BY created_at DESC")
        
        # Disk bilgilerini JSON parse et
        import json
        for server in servers:
            try:
                if server['disks']:
                    server['disks'] = json.loads(server['disks'])
                else:
                    server['disks'] = []
            except:
                server['disks'] = []
        
        # Sunucu listesi sayfası ziyaret edildiğini logla
        log_activity(session['user_id'], session['username'], 'server_list', 
                    f'Sunucu listesi sayfasını ziyaret etti - {len(servers)} sunucu listelendi', 'sunuculari-listele')
        
        return render_template_string(TEMPLATE_SUNUCULARI_LISTELE, 
                                    servers=servers, 
                                    theme_script=THEME_SCRIPT)
    except Exception as e:
        flash(f"Sunucu listesi alınamadı: {str(e)}", "danger")
        return render_template_string(TEMPLATE_SUNUCULARI_LISTELE, 
                                    servers=[], 
                                    theme_script=THEME_SCRIPT)

# Sunucu listesi Excel export
@app.route("/sunucu-excel-export")
@require_auth("multiquery")
def sunucu_excel_export():
    """Sunucu listesini Excel formatında export et"""
    try:
        # Veritabanından tüm sunucu bilgilerini al
        servers = db_query("SELECT * FROM sunucu_envanteri ORDER BY created_at DESC")
        
        # Excel dosyası oluştur
        import pandas as pd
        from io import BytesIO
        
        # Sunucu verilerini Excel formatına dönüştür
        excel_data = []
        for server in servers:
            # Disk bilgilerini formatla
            import json
            try:
                # Disks alanı zaten dictionary ise direkt kullan
                if isinstance(server['disks'], list):
                    disks = server['disks']
                elif isinstance(server['disks'], str):
                    disks = json.loads(server['disks']) if server['disks'] else []
                else:
                    disks = []
                
                disk_info = ""
                for disk in disks:
                    if isinstance(disk, dict):
                        disk_info += f"{disk.get('device', 'N/A')} ({disk.get('mount', 'N/A')}): {disk.get('size', 'N/A')} toplam, {disk.get('used', 'N/A')} kullanılan, {disk.get('available', 'N/A')} boş, %{disk.get('percent', 'N/A')}\n"
                    else:
                        disk_info += str(disk) + "\n"
                disk_info = disk_info.strip()
            except Exception as e:
                print(f"Disk bilgisi formatlanırken hata: {e}")
                disk_info = str(server['disks']) if server['disks'] else "N/A"
            
            excel_data.append({
                'Hostname': server['hostname'],
                'IP Adresi': server['ip'],
                'SSH Port': server['ssh_port'],
                'SSH Kullanıcı': server['ssh_user'],
                'İşletim Sistemi': server['os_info'],
                'CPU Bilgisi': server['cpu_info'],
                'CPU Core Sayısı': server['cpu_cores'],
                'Toplam RAM': server['ram_total'],
                'Disk Bilgileri': disk_info,
                'Sistem Uptime': server['uptime'],
                'PostgreSQL Durumu': server['postgresql_status'],
                'PostgreSQL Versiyonu': server['postgresql_version'],
                'PostgreSQL Replication': server['postgresql_replication'],
                'pgBackRest Durumu': server['pgbackrest_status'],
                'Eklenme Tarihi': server['created_at'],
                'Güncelleme Tarihi': server['updated_at']
            })
        
        # DataFrame oluştur
        df = pd.DataFrame(excel_data)
        
        # Excel dosyası oluştur
        output = BytesIO()
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            df.to_excel(writer, sheet_name='Sunucu Envanteri', index=False)
            
            # Worksheet'i al ve sütun genişliklerini ayarla
            worksheet = writer.sheets['Sunucu Envanteri']
            for column in worksheet.columns:
                max_length = 0
                column_letter = column[0].column_letter
                for cell in column:
                    try:
                        if len(str(cell.value)) > max_length:
                            max_length = len(str(cell.value))
                    except:
                        pass
                adjusted_width = min(max_length + 2, 50)
                worksheet.column_dimensions[column_letter].width = adjusted_width
        
        output.seek(0)
        
        # Dosya adı
        from datetime import datetime
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"sunucu_envanteri_{timestamp}.xlsx"
        
        # Log export işlemini kaydet
        log_activity(session['user_id'], session['username'], 'excel_export', 
                    f"Sunucu envanteri Excel export - {len(servers)} sunucu", 'sunucu-excel-export')
        
        return send_file(
            output,
            as_attachment=True,
            download_name=filename,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        )
        
    except Exception as e:
        flash(f"Excel export hatası: {str(e)}", "danger")
        return redirect(url_for("sunuculari_listele"))

@app.route("/add_server", methods=["POST"])
@require_auth("multiquery")
def add_server():
    name = request.form.get("name", "").strip()
    host = request.form.get("host", "").strip()
    port_raw = request.form.get("port")
    port = int(port_raw) if port_raw else 5432
    dbname = request.form.get("dbname", "").strip()
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    if not all([name, host, dbname, username]):
        flash("Zorunlu alanları doldurunuz.", "danger")
        return redirect(url_for("multiquery"))
    try:
        db_insert_server(name, host, port, dbname, username, password)
        server_info = {"name": name, "host": host, "port": port, "dbname": dbname}
        log_server_operation(session['user_id'], session['username'], 'add', server_info, True)
        flash("Sunucu eklendi.", "success")
    except Exception as e:
        server_info = {"name": name, "host": host, "port": port, "dbname": dbname}
        log_server_operation(session['user_id'], session['username'], 'add', server_info, False, str(e))
        flash(f"Sunucu eklenemedi: {e}", "danger")
    return redirect(url_for("multiquery"))

@app.route("/delete_server/<int:sid>", methods=["POST"])
@require_auth("multiquery")
def delete_server(sid: int):
    try:
        # Silinecek sunucuyu bul
        server = db_query("SELECT * FROM servers WHERE id=?", (sid,))
        if server:
            server_info = dict(server[0])
            db_execute("DELETE FROM servers WHERE id=?", (sid,))
            log_server_operation(session['user_id'], session['username'], 'delete', server_info, True)
        flash("Sunucu silindi.", "info")
    except Exception as e:
        flash(f"Silme hatası: {e}", "danger")
    return redirect(url_for("multiquery"))

@app.route("/edit_server", methods=["POST"])
@require_auth("multiquery")
def edit_server():
    server_id = request.form.get("edit_server_id")
    name = request.form.get("edit_name")
    host = request.form.get("edit_host")
    port = request.form.get("edit_port", 5432)
    dbname = request.form.get("edit_dbname")
    username = request.form.get("edit_username")
    password = request.form.get("edit_password")
    
    if not all([name, host, dbname, username]):
        flash("Tüm alanlar doldurulmalıdır.", "danger")
        return redirect(url_for("multiquery"))
    
    try:
        # Eğer parola girilmişse güncelle, girilmemişse eski parolayı koru
        if password:
            db_execute(
                "UPDATE servers SET name = ?, host = ?, port = ?, dbname = ?, username = ?, password = ? WHERE id = ?",
                [name, host, int(port), dbname, username, password, server_id]
            )
        else:
            db_execute(
                "UPDATE servers SET name = ?, host = ?, port = ?, dbname = ?, username = ? WHERE id = ?",
                [name, host, int(port), dbname, username, server_id]
            )
        
        server_info = {"name": name, "host": host, "port": port, "dbname": dbname, "id": server_id}
        log_server_operation(session['user_id'], session['username'], 'edit', server_info, True)
        flash("Sunucu başarıyla güncellendi.", "success")
    except Exception as e:
        server_info = {"name": name, "host": host, "port": port, "dbname": dbname, "id": server_id}
        log_server_operation(session['user_id'], session['username'], 'edit', server_info, False, str(e))
        flash(f"Sunucu güncellenirken hata oluştu: {str(e)}", "danger")
    
    return redirect(url_for("multiquery"))

@app.route("/run_query", methods=["POST"])
@require_auth("multiquery")
def run_query():
    sql = request.form.get("sql", "").strip()
    selected_ids = request.form.getlist("server_id")
    if not sql:
        flash("Lütfen çalıştırılacak SQL'i girin.", "warning")
        return redirect(url_for("multiquery"))
    if not selected_ids:
        flash("En az bir sunucu seçin.", "warning")
        return redirect(url_for("multiquery"))

    # Seçilen sunucuları al (hem manuel hem envanter)
    servers = []
    for server_id in selected_ids:
        if server_id.startswith('inv_'):
            # Envanter sunucusu
            hostname = server_id.replace('inv_', '')
            inventory_data = db_query("""
                SELECT hostname, ip, ssh_port, ssh_user, ssh_password, postgresql_status, postgresql_version
                FROM sunucu_envanteri 
                WHERE hostname = ? AND postgresql_status = 'Var'
            """, (hostname,))
            
            if inventory_data:
                inv_server = inventory_data[0]
                decrypted_password = decrypt_password(inv_server['ssh_password']) if inv_server['ssh_password'] else ''
                
                # PostgreSQL port'unu tespit et
                postgres_port = 5432  # Varsayılan port
                
                try:
                    if decrypted_password:
                        import paramiko
                        ssh = paramiko.SSHClient()
                        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                        ssh.connect(hostname=inv_server['ip'], port=int(inv_server['ssh_port']), 
                                   username=inv_server['ssh_user'], password=decrypted_password, timeout=5)
                        
                        # PostgreSQL port'unu tespit et - detaylı kontrol
                        print(f"Port tespit ediliyor: {inv_server['hostname']}")
                        
                        # Yöntem 1: netstat ile tüm PostgreSQL portlarını listele
                        stdin, stdout, stderr = ssh.exec_command("netstat -tlnp 2>/dev/null | grep postgres")
                        netstat_output = stdout.read().decode().strip()
                        print(f"Netstat çıktısı: {netstat_output}")
                        
                        if netstat_output:
                            lines = netstat_output.split('\n')
                            for line in lines:
                                if 'postgres' in line and 'LISTEN' in line:
                                    parts = line.split()
                                    if len(parts) >= 4:
                                        address_port = parts[3]
                                        if ':' in address_port:
                                            port_part = address_port.split(':')[-1]
                                            if port_part.isdigit():
                                                postgres_port = int(port_part)
                                                print(f"PostgreSQL port tespit edildi (netstat): {inv_server['hostname']} -> {postgres_port}")
                                                break
                        
                        # Yöntem 2: ss komutu ile kontrol
                        if postgres_port == 5432:
                            stdin, stdout, stderr = ssh.exec_command("ss -tlnp 2>/dev/null | grep postgres")
                            ss_output = stdout.read().decode().strip()
                            print(f"SS çıktısı: {ss_output}")
                            
                            if ss_output:
                                lines = ss_output.split('\n')
                                for line in lines:
                                    if 'postgres' in line and 'LISTEN' in line:
                                        parts = line.split()
                                        if len(parts) >= 4:
                                            address_port = parts[3]
                                            if ':' in address_port:
                                                port_part = address_port.split(':')[-1]
                                                if port_part.isdigit():
                                                    postgres_port = int(port_part)
                                                    print(f"PostgreSQL port tespit edildi (ss): {inv_server['hostname']} -> {postgres_port}")
                                                    break
                        
                        # Yöntem 3: PostgreSQL konfigürasyon dosyasından port oku
                        if postgres_port == 5432:
                            stdin, stdout, stderr = ssh.exec_command("sudo -u postgres psql -t -c \"SHOW port;\" 2>/dev/null")
                            psql_output = stdout.read().decode().strip()
                            if psql_output and psql_output.isdigit():
                                postgres_port = int(psql_output)
                                print(f"PostgreSQL port tespit edildi (psql): {inv_server['hostname']} -> {postgres_port}")
                        
                        print(f"Final PostgreSQL port: {inv_server['hostname']} -> {postgres_port}")
                        
                        # PostgreSQL bağlantı testi
                        try:
                            import psycopg2
                            test_conn = psycopg2.connect(
                                host=inv_server['ip'],
                                port=postgres_port,
                                database='postgres',
                                user='postgres',
                                password=decrypted_password,
                                connect_timeout=5
                            )
                            test_conn.close()
                            print(f"PostgreSQL bağlantı testi başarılı: {inv_server['hostname']}:{postgres_port}")
                        except Exception as conn_e:
                            print(f"PostgreSQL bağlantı testi başarısız: {inv_server['hostname']}:{postgres_port} - {conn_e}")
                            
                            # Alternatif portları dene
                            alternative_ports = [5433, 5434, 5435, 5436, 5437, 5438, 5439, 5440]
                            for alt_port in alternative_ports:
                                try:
                                    test_conn = psycopg2.connect(
                                        host=inv_server['ip'],
                                        port=alt_port,
                                        database='postgres',
                                        user='postgres',
                                        password=decrypted_password,
                                        connect_timeout=3
                                    )
                                    test_conn.close()
                                    postgres_port = alt_port
                                    print(f"Alternatif port bulundu: {inv_server['hostname']}:{alt_port}")
                                    break
                                except:
                                    continue
                        
                        ssh.close()
                except Exception as e:
                    print(f"Port tespit hatası {inv_server['hostname']}: {e}")
                    postgres_port = 5432  # Hata durumunda varsayılan port
                
                servers.append({
                    'id': server_id,
                    'name': f"{inv_server['hostname']} (Envanter)",
                    'host': inv_server['ip'],
                    'port': postgres_port,
                    'dbname': 'postgres',
                    'username': 'postgres',
                    'password': decrypted_password,
                    'is_inventory': True
                })
        else:
            # Manuel sunucu
            try:
                rows = db_query("SELECT * FROM servers WHERE id = ?", (int(server_id),))
                if rows:
                    servers.append(dict(rows[0]))
            except:
                pass

    results: List[Dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        futures = {ex.submit(run_sql_on_server, srv, sql): srv for srv in servers}
        for fut in as_completed(futures):
            results.append(fut.result())

    base_cols = ["Server", "Host", "Port", "DB"]
    union_cols_order: List[str] = []
    seen = set()
    ok_results = [r for r in results if r.get("ok") and r.get("columns")]
    for r in ok_results:
        for c in r["columns"]:
            if c not in seen:
                seen.add(c)
                union_cols_order.append(c)
    merged_columns = base_cols + (union_cols_order or ["status"])

    merged_rows: List[Dict[str, Any]] = []
    errors: List[Dict[str, Any]] = []
    for r in results:
        s = r["info"]
        if r.get("ok") and r.get("columns"):
            for row in r["rows"]:
                new_row = {"Server": s["name"], "Host": s["host"], "Port": s["port"], "DB": s["dbname"]}
                for c in union_cols_order: new_row[c] = row.get(c, "")
                merged_rows.append(new_row)
        elif r.get("ok") and not r.get("columns"):
            merged_rows.append({"Server": s["name"], "Host": s["host"], "Port": s["port"], "DB": s["dbname"], "status": "OK"})
        else:
            errors.append(r)
            merged_rows.append({"Server": s["name"], "Host": s["host"], "Port": s["port"], "DB": s["dbname"], "status": f"Hata: {r.get('error','')}"})

    servers_min = [{"name": s["name"], "host": s["host"], "port": s["port"], "dbname": s["dbname"]} for s in servers]
    merged = {"columns": merged_columns, "rows": merged_rows}

    # Detaylı SQL sorgu logging'i
    log_sql_query(session['user_id'], session['username'], sql, servers, results, 'multiquery')

    return render_template_string(
        TEMPLATE_RESULTS,
        title=f"{APP_TITLE} - Sonuçlar",
        sql=sql,
        selected_ids=selected_ids,
        servers=servers_min,
        merged=merged,
        errors=errors,
        theme_script=THEME_SCRIPT,
    )

@app.route("/export_merged_csv", methods=["POST"])
@require_auth("multiquery")
def export_merged_csv():
    from io import StringIO, BytesIO
    import csv as _csv
    sql = request.form.get("sql", "")
    ids = request.form.getlist("server_id")
    if not sql or not ids:
        flash("Birleşik dışa aktarım için SQL ve sunucu seçimi gerekiyor.", "warning")
        return redirect(url_for("multiquery"))

    # Manuel ve envanter sunucularını ayır
    manual_ids = []
    inventory_ids = []
    
    for server_id in ids:
        if server_id.startswith('inv_'):
            inventory_ids.append(server_id.replace('inv_', ''))
        else:
            manual_ids.append(server_id)
    
    servers = []
    
    # Manuel sunucuları al
    if manual_ids:
        placeholders = _in_clause_placeholders(len(manual_ids))
        rows = db_query(f"SELECT * FROM servers WHERE id IN ({placeholders})", tuple(map(int, manual_ids)))
        servers.extend([dict(r) for r in rows])
    
    # Envanter sunucularını al
    if inventory_ids:
        placeholders = _in_clause_placeholders(len(inventory_ids))
        inventory_rows = db_query(f"SELECT hostname, ip, ssh_port, ssh_user, ssh_password, postgresql_status, postgresql_version FROM sunucu_envanteri WHERE hostname IN ({placeholders})", tuple(inventory_ids))
        
        for inv_row in inventory_rows:
            inv_server = dict(inv_row)
            decrypted_password = decrypt_password(inv_server['ssh_password']) if inv_server['ssh_password'] else ''
            
            # PostgreSQL port'unu tespit et
            postgres_port = 5432
            try:
                if decrypted_password:
                    import paramiko
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    ssh.connect(hostname=inv_server['ip'], port=int(inv_server['ssh_port']), 
                               username=inv_server['ssh_user'], password=decrypted_password, timeout=5)
                    
                    # Port tespit et
                    stdin, stdout, stderr = ssh.exec_command("netstat -tlnp 2>/dev/null | grep postgres | head -1 | awk '{print $4}' | cut -d: -f2")
                    port_output = stdout.read().decode().strip()
                    if port_output and port_output.isdigit():
                        postgres_port = int(port_output)
                    
                    ssh.close()
            except:
                pass
            
            servers.append({
                'id': f"inv_{inv_server['hostname']}",
                'name': f"{inv_server['hostname']} (Envanter)",
                'host': inv_server['ip'],
                'port': postgres_port,
                'dbname': 'postgres',
                'username': 'postgres',
                'password': decrypted_password
            })

    results: List[Dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        futs = {ex.submit(run_sql_on_server, s, sql): s for s in servers}
        for f in as_completed(futs):
            results.append(f.result())

    base = ["Server", "Host", "Port", "DB"]
    union_cols: List[str] = []
    seen = set()
    for r in results:
        if r.get("ok") and r.get("columns"):
            for c in r["columns"]:
                if c not in seen:
                    seen.add(c); union_cols.append(c)
    header = base + (union_cols or ["status"])

    def norm(v):
        if v is None: return ""
        return str(v).replace("\r", " ").replace("\n", " ").replace("\t", " ")

    text_buf = StringIO()
    writer = _csv.writer(text_buf, delimiter=';', lineterminator='\r\n', quoting=_csv.QUOTE_MINIMAL)
    writer.writerow(header)
    for r in results:
        info = r["info"]
        if r.get("ok") and r.get("columns"):
            for row in r["rows"]:
                out = [info["name"], info["host"], info["port"], info["dbname"]]
                out += [norm(row.get(c, "")) for c in union_cols]
                writer.writerow(out)
        elif r.get("ok") and not r.get("columns"):
            writer.writerow([info["name"], info["host"], info["port"], info["dbname"], "OK"])
        else:
            writer.writerow([info["name"], info["host"], info["port"], info["dbname"], f"Hata: {norm(r.get('error',''))}"])

    # Log CSV export işlemi
    server_names = ", ".join([s["name"] for s in servers])
    log_activity(session['user_id'], session['username'], 'export_csv', 
                f"CSV export - Sunucular: {server_names} - Sorgu: {sql[:50]}{'...' if len(sql) > 50 else ''}", 'multiquery')

    data = text_buf.getvalue().encode("utf-8-sig")
    bio = BytesIO(data)
    return send_file(bio, as_attachment=True, download_name="merged_results.csv", mimetype="text/csv")

@app.route("/export_zip", methods=["POST"])
@require_auth("multiquery")
def export_zip():
    from io import BytesIO, StringIO
    import zipfile, csv, re
    sql = request.form.get("sql", "")
    ids = request.form.getlist("server_id")
    if not sql or not ids:
        flash("Dışa aktarım için SQL ve sunucu seçimi gerekiyor.", "warning")
        return redirect(url_for("multiquery"))

    # Manuel ve envanter sunucularını ayır
    manual_ids = []
    inventory_ids = []
    
    for server_id in ids:
        if server_id.startswith('inv_'):
            inventory_ids.append(server_id.replace('inv_', ''))
        else:
            manual_ids.append(server_id)
    
    servers = []
    
    # Manuel sunucuları al
    if manual_ids:
        placeholders = _in_clause_placeholders(len(manual_ids))
        rows = db_query(f"SELECT * FROM servers WHERE id IN ({placeholders})", tuple(map(int, manual_ids)))
        servers.extend([dict(r) for r in rows])
    
    # Envanter sunucularını al
    if inventory_ids:
        placeholders = _in_clause_placeholders(len(inventory_ids))
        inventory_rows = db_query(f"SELECT hostname, ip, ssh_port, ssh_user, ssh_password, postgresql_status, postgresql_version FROM sunucu_envanteri WHERE hostname IN ({placeholders})", tuple(inventory_ids))
        
        for inv_row in inventory_rows:
            inv_server = dict(inv_row)
            decrypted_password = decrypt_password(inv_server['ssh_password']) if inv_server['ssh_password'] else ''
            
            # PostgreSQL port'unu tespit et
            postgres_port = 5432
            try:
                if decrypted_password:
                    import paramiko
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    ssh.connect(hostname=inv_server['ip'], port=int(inv_server['ssh_port']), 
                               username=inv_server['ssh_user'], password=decrypted_password, timeout=5)
                    
                    # Port tespit et
                    stdin, stdout, stderr = ssh.exec_command("netstat -tlnp 2>/dev/null | grep postgres | head -1 | awk '{print $4}' | cut -d: -f2")
                    port_output = stdout.read().decode().strip()
                    if port_output and port_output.isdigit():
                        postgres_port = int(port_output)
                    
                    ssh.close()
            except:
                pass
            
            servers.append({
                'id': f"inv_{inv_server['hostname']}",
                'name': f"{inv_server['hostname']} (Envanter)",
                'host': inv_server['ip'],
                'port': postgres_port,
                'dbname': 'postgres',
                'username': 'postgres',
                'password': decrypted_password
            })

    mem = BytesIO()
    with zipfile.ZipFile(mem, mode='w', compression=zipfile.ZIP_DEFLATED) as zf:
        for s in servers:
            r = run_sql_on_server(s, sql)
            safe_name = re.sub(r"[^A-Za-z0-9._-]+", "_", f"{s['name']}_{s['host']}_{s['port']}_{s['dbname']}")
            fname = f"{safe_name}.csv"
            sio = StringIO()
            w = csv.writer(sio)
            if r.get('ok') and r.get('columns'):
                w.writerow(r['columns'])
                for row in r['rows']:
                    w.writerow([str(row.get(col, "")) for col in r['columns']])
            elif r.get('ok') and not r.get('columns'):
                w.writerow(["status"]); w.writerow(["OK"])
            else:
                w.writerow(["error"]); w.writerow([str(r.get('error',''))])
            zf.writestr(fname, sio.getvalue())
    # Log ZIP export işlemi
    server_names = ", ".join([s["name"] for s in servers])
    log_activity(session['user_id'], session['username'], 'export_zip', 
                f"ZIP export - Sunucular: {server_names} - Sorgu: {sql[:50]}{'...' if len(sql) > 50 else ''}", 'multiquery')

    mem.seek(0)
    return send_file(mem, as_attachment=True, download_name="query_results_csv.zip", mimetype="application/zip")

@app.route("/api/servers")
@require_auth("multiquery")
def api_servers():
    rows = db_query("SELECT id, name, host, port, dbname, username FROM servers ORDER BY id DESC")
    return jsonify(rows)

@app.route("/api/admin/users")
@require_auth("admin_panel")
def api_admin_users():
    """Admin panel için kullanıcı listesi"""
    if not session.get('is_admin'):
        return jsonify({"error": "Yetkiniz yok"}), 403
    
    users = db_query("SELECT id, username, full_name, is_active, is_admin, last_login FROM users ORDER BY id")
    return jsonify(users)

@app.route("/api/admin/today-queries")
@require_auth("admin_panel")
def api_admin_today_queries():
    """Admin panel için bugünkü sorgu listesi"""
    if not session.get('is_admin'):
        return jsonify({"error": "Yetkiniz yok"}), 403
    
    from datetime import datetime
    today = datetime.now().strftime('%Y-%m-%d')
    
    queries = db_query("""
        SELECT timestamp, username, action, details, page_name 
        FROM activity_logs 
        WHERE DATE(timestamp) = ? AND action LIKE '%sorgu%'
        ORDER BY timestamp DESC 
        LIMIT 100
    """, (today,))
    
    return jsonify(queries)

@app.route("/api/stats")
@require_auth()
def api_stats():
    """Ana sayfa istatistikleri için API endpoint"""
    try:
        # Sunucu sayısı
        servers_count = db_query("SELECT COUNT(*) as count FROM servers")[0]['count']
        
        # Aktif kullanıcı sayısı
        users_count = db_query("SELECT COUNT(*) as count FROM users WHERE is_active = 1")[0]['count']
        
        # Bugünkü sorgu sayısı (log tablosundan) - sadece gerçek sorgular
        from datetime import datetime
        today = datetime.now().strftime('%Y-%m-%d')
        today_queries = db_query("SELECT COUNT(*) as count FROM activity_logs WHERE date(timestamp) = ? AND action LIKE '%sorgu%'", (today,))[0]['count']
        
        return jsonify({
            'servers': servers_count,
            'users': users_count,
            'todayQueries': today_queries,
            'status': 'online'
        })
    except Exception as e:
        return jsonify({
            'servers': 0,
            'users': 0,
            'todayQueries': 0,
            'status': 'error'
        })

@app.route("/pg_install")
@require_auth("pg_install")
def pg_install():
    """PostgreSQL Installation sayfası"""
    try:
        if not PG_INSTALL_AVAILABLE:
            error_html = """
            <!DOCTYPE html>
            <html>
            <head>
                <title>PostgreSQL Installation - Hata</title>
                <meta charset="utf-8">
                <style>
                    body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
                    .error-box { background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                    h1 { color: #e74c3c; }
                    .btn { background: #3498db; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; display: inline-block; margin-top: 20px; }
                </style>
            </head>
            <body>
                <div class="error-box">
                    <h1>🐘 PostgreSQL Installation</h1>
                    <p><strong>Hata:</strong> PostgreSQL Installation modülü yüklenemedi</p>
                    <p>Bu modül şu anda kullanılamıyor. Lütfen daha sonra tekrar deneyin.</p>
                    <a href="/" class="btn">🏠 Ana Sayfaya Dön</a>
                </div>
            </body>
            </html>
            """
            return error_html
        
        # Template cache'den kontrol et
        global _template_cache
        cache_key = "pg_install_form"
        if cache_key not in _template_cache:
            # FORM_HTML template'ini al ve cache'le
            if hasattr(pstandaloneinstall, 'FORM_HTML'):
                _template_cache[cache_key] = pstandaloneinstall.FORM_HTML
            else:
                return "<h1>Hata</h1><p>FORM_HTML template'i bulunamadı</p><a href='/'>Ana Sayfaya Dön</a>"
        
        return _template_cache[cache_key]
        
    except Exception as e:
        error_html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>PostgreSQL Installation - Hata</title>
            <meta charset="utf-8">
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
                .error-box {{ background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
                h1 {{ color: #e74c3c; }}
                .btn {{ background: #3498db; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; display: inline-block; margin-top: 20px; }}
                .error-detail {{ background: #f8f9fa; padding: 15px; border-left: 4px solid #e74c3c; margin: 15px 0; }}
            </style>
        </head>
        <body>
            <div class="error-box">
                <h1>🐘 PostgreSQL Installation</h1>
                <p><strong>Hata:</strong> PostgreSQL Installation sayfası yüklenemedi</p>
                <div class="error-detail">
                    <strong>Hata Detayı:</strong> {str(e)}
                </div>
                <a href="/" class="btn">🏠 Ana Sayfaya Dön</a>
            </div>
        </body>
        </html>
        """
        return error_html

@app.route("/pg_prepare_install", methods=["POST"])
@require_auth("pg_install")
def pg_prepare_install():
    """PostgreSQL Installation hazırlık endpoint'i"""
    try:
        if not PG_INSTALL_AVAILABLE:
            return jsonify({"error": "PostgreSQL Installation modülü yüklenemedi"}), 500
        
        # pstandaloneinstall'daki prepare_install fonksiyonunu çağır
        return pstandaloneinstall.prepare_install()
    except Exception as e:
        return jsonify({"error": f"Hazırlık hatası: {str(e)}"}), 500

@app.route("/pg_install_stream", methods=["GET"])
@require_auth("pg_install")
def pg_install_stream():
    """PostgreSQL Installation canlı stream endpoint'i"""
    try:
        if not PG_INSTALL_AVAILABLE:
            return "SSE bağlantısı kurulamadı", 500
        
        # pstandaloneinstall'daki install_stream fonksiyonunu çağır
        return pstandaloneinstall.install_stream()
    except Exception as e:
        from flask import Response
        error_msg = str(e)
        def error_stream():
            yield f"data: [ERR] Stream hatası: {error_msg}\n\n"
        return Response(error_stream(), mimetype="text/event-stream")

# Admin Panel Routes
@app.route("/admin")
@require_auth("admin_panel")
def admin_panel():
    """Admin paneli ana sayfası"""
    # Sadece admin kullanıcılar erişebilir
    if not session.get('is_admin'):
        flash("Bu sayfaya erişim yetkiniz yok!", "danger")
        return redirect(url_for("landing"))
    
    # Arama parametreleri
    search = request.args.get('search', '').strip()
    page_size = int(request.args.get('page_size', 100))
    page = int(request.args.get('page', 1))
    active_tab = request.args.get('tab', 'dashboard')  # Varsayılan olarak users tab'ı
    
    # Kullanıcıları getir
    users = db_query("SELECT * FROM users ORDER BY id")
    
    # Log sorgusu oluştur
    log_query = "SELECT * FROM activity_logs"
    params = []
    
    if search:
        log_query += " WHERE username LIKE ? OR action LIKE ? OR page_name LIKE ? OR ip_address LIKE ?"
        search_param = f"%{search}%"
        params = [search_param, search_param, search_param, search_param]
    
    # Toplam log sayısını al
    count_query = log_query.replace("SELECT *", "SELECT COUNT(*)")
    count_result = db_query(count_query, params) if params else db_query(count_query)
    # COUNT sorgusu için özel işlem
    if count_result and len(count_result) > 0:
        # COUNT sorgusu bir dictionary döndürür: {'COUNT(*)': sayı}
        count_dict = count_result[0]
        total_logs = list(count_dict.values())[0] if count_dict else 0
    else:
        total_logs = 0
    
    # Sayfalama için LIMIT ve OFFSET ekle
    offset = (page - 1) * page_size
    log_query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
    params.extend([page_size, offset])
    
    logs = db_query(log_query, params)
    
    # Sayfa bilgileri
    total_pages = (total_logs + page_size - 1) // page_size
    
    # Sayfa yetkileri tanımları
    page_permissions = {
        'multiquery': {'name': 'Multiquery', 'description': 'PostgreSQL sorgu sayfası'},
        'pg_install': {'name': 'PostgreSQL Installation', 'description': 'PostgreSQL kurulum sayfası'},
        'faydali_linkler': {'name': 'Faydalı Linkler', 'description': 'Faydalı linkler menüsü'},
        'view_logs': {'name': 'Log Görüntüleme', 'description': 'Aktivite loglarını görüntüleme'},
        'envanter': {'name': 'Sunucu Envanteri', 'description': 'Sunucu envanter yönetimi'},
        'healthcheck': {'name': 'Healthcheck', 'description': 'Sunucu sağlık kontrolü ve geçmişi'},
        'admin_panel': {'name': 'Admin Panel', 'description': 'Admin yönetim paneli'}
    }
    
    # Her kullanıcının yetkilerini al
    user_permissions = {}
    for user in users:
        if not user['is_admin']:  # Admin kullanıcılar tüm yetkilere sahip
            perms = db_query("SELECT page_name, can_access FROM user_permissions WHERE user_id = ?", [user['id']])
            user_perms = {}
            for perm in perms:
                user_perms[perm['page_name']] = perm['can_access']
            user_permissions[user['id']] = user_perms
    
    return render_template_string(TEMPLATE_ADMIN, users=users, logs=logs, 
                                user_permissions=user_permissions, page_permissions=page_permissions,
                                search=search, page_size=page_size, page=page, total_logs=total_logs, total_pages=total_pages,
                                active_tab=active_tab)

@app.route("/admin/add_user", methods=["POST"])
@require_auth("admin_panel")
def admin_add_user():
    """Yeni kullanıcı ekle"""
    if not session.get('is_admin'):
        flash("Bu işlem için yetkiniz yok!", "danger")
        return redirect(url_for("admin_panel"))
    
    username = request.form.get("username")
    full_name = request.form.get("full_name")
    password = request.form.get("password")
    is_admin = False  # Admin yetkisi sadece admin kullanıcılarda kalacak
    
    # Seçilen yetkileri al (normal kullanıcı için)
    selected_permissions = []
    permission_pages = ['multiquery', 'pg_install', 'faydali_linkler', 'view_logs', 'envanter', 'healthcheck']
    
    for page in permission_pages:
        if request.form.get(page):
            selected_permissions.append(page)
    
    try:
        password_hash = hash_password(password)
        with closing(get_meta_conn()) as con:
            cur = con.execute("""
                INSERT INTO users (username, password_hash, full_name, is_admin, is_active)
                VALUES (?, ?, ?, ?, 1)
            """, [username, password_hash, full_name, is_admin])
            user_id = cur.lastrowid
            
            # Seçilen yetkileri ver
            for page in selected_permissions:
                con.execute("""
                    INSERT INTO user_permissions (user_id, page_name, can_access)
                    VALUES (?, ?, 1)
                """, [user_id, page])
            
            con.commit()
        
        permissions_text = ", ".join(selected_permissions) if selected_permissions else "Hiçbir yetki verilmedi"
        log_activity(session['user_id'], session['username'], 'add_user', 
                    f'Kullanıcı: {username} ({full_name}) | Yetkiler: {permissions_text} | Durum: Aktif', 'admin_panel')
        flash("Kullanıcı başarıyla eklendi!", "success")
    except Exception as e:
        flash(f"Kullanıcı eklenirken hata: {str(e)}", "danger")
    
    return redirect(url_for("admin_panel"))

@app.route("/admin/toggle_user/<int:user_id>")
@require_auth("admin_panel")
def admin_toggle_user(user_id):
    """Kullanıcıyı aktif/pasif yap"""
    if not session.get('is_admin'):
        flash("Bu işlem için yetkiniz yok!", "danger")
        return redirect(url_for("admin_panel"))
    
    # Admin kullanıcıyı deaktif etmeye izin verme
    user = db_query("SELECT is_admin FROM users WHERE id = ?", [user_id])
    if user and user[0]['is_admin']:
        flash("Admin kullanıcı deaktif edilemez!", "danger")
        return redirect(url_for("admin_panel"))
    
    try:
        # Mevcut durumu tersine çevir
        current_status = db_query("SELECT is_active FROM users WHERE id = ?", [user_id])
        if current_status:
            new_status = not current_status[0]['is_active']
            db_execute("UPDATE users SET is_active = ? WHERE id = ?", [new_status, user_id])
            
            username = db_query("SELECT username FROM users WHERE id = ?", [user_id])[0]['username']
            status_text = "Aktif" if new_status else "Deaktif"
            log_activity(session['user_id'], session['username'], 'toggle_user', 
                        f'Kullanıcı: {username} (ID: {user_id}) | Eski durum: {"Deaktif" if not new_status else "Aktif"} | Yeni durum: {status_text}', 'admin_panel')
            flash(f"Kullanıcı {'aktif' if new_status else 'deaktif'} edildi!", "success")
    except Exception as e:
        flash(f"İşlem sırasında hata: {str(e)}", "danger")
    
    return redirect(url_for("admin_panel"))

@app.route("/admin/edit_user/<int:user_id>", methods=["GET", "POST"])
@require_auth("admin_panel")
def admin_edit_user(user_id):
    """Kullanıcı düzenleme sayfası"""
    if not session.get('is_admin'):
        flash("Bu işlem için yetkiniz yok!", "danger")
        return redirect(url_for("admin_panel"))
    
    # Kullanıcıyı bul
    user = db_query("SELECT * FROM users WHERE id = ?", [user_id])
    if not user:
        flash("Kullanıcı bulunamadı!", "danger")
        return redirect(url_for("admin_panel"))
    
    user = user[0]
    
    if request.method == "POST":
        username = request.form.get("username")
        full_name = request.form.get("full_name")
        password = request.form.get("password")
        # Admin yetkisi değiştirilemez - sadece admin kullanıcılarda kalacak
        is_admin = user['is_admin']
        
        try:
            if password:
                # Şifre değiştirilmişse
                password_hash = hash_password(password)
                db_execute("""
                    UPDATE users SET username = ?, full_name = ?, password_hash = ?
                    WHERE id = ?
                """, [username, full_name, password_hash, user_id])
            else:
                # Şifre değiştirilmemişse
                db_execute("""
                    UPDATE users SET username = ?, full_name = ?
                    WHERE id = ?
                """, [username, full_name, user_id])
            
            # Yetkileri güncelle (sadece admin kullanıcılar ve admin kullanıcı değilse)
            if session.get('is_admin') and not user['is_admin']:
                # Mevcut yetkileri sil
                db_execute("DELETE FROM user_permissions WHERE user_id = ?", [user_id])
                
                # Yeni yetkileri ekle (admin panel yetkisi hariç)
                permission_pages = ['multiquery', 'pg_install', 'faydali_linkler', 'view_logs', 'envanter', 'healthcheck']
                for page in permission_pages:
                    if request.form.get(page):
                        db_execute("""
                            INSERT INTO user_permissions (user_id, page_name, can_access)
                            VALUES (?, ?, 1)
                        """, [user_id, page])
            
            # Yetki değişikliklerini logla
            permission_changes = []
            if session.get('is_admin') and not user['is_admin']:
                permission_pages = ['multiquery', 'pg_install', 'faydali_linkler', 'view_logs', 'envanter', 'healthcheck']
                for page in permission_pages:
                    if request.form.get(page):
                        permission_changes.append(page)
            
            log_details = f'Kullanıcı düzenlendi: {username} ({full_name})'
            if permission_changes:
                log_details += f' - Yeni yetkiler: {", ".join(permission_changes)}'
            
            log_activity(session['user_id'], session['username'], 'edit_user', log_details, 'admin_panel')
            flash("Kullanıcı başarıyla güncellendi!", "success")
            return redirect(url_for("admin_panel"))
        except Exception as e:
            flash(f"Kullanıcı güncellenirken hata: {str(e)}", "danger")
    
    # Mevcut yetkileri al
    current_permissions = db_query("SELECT page_name, can_access FROM user_permissions WHERE user_id = ?", [user_id])
    user_perms = {}
    for perm in current_permissions:
        user_perms[perm['page_name']] = perm['can_access']
    
    # Sayfa yetkileri tanımları
    page_permissions = {
        'multiquery': {'name': 'Multiquery', 'description': 'PostgreSQL sorgu sayfası'},
        'pg_install': {'name': 'PostgreSQL Installation', 'description': 'PostgreSQL kurulum sayfası'},
        'faydali_linkler': {'name': 'Faydalı Linkler', 'description': 'Faydalı linkler menüsü'},
        'view_logs': {'name': 'Log Görüntüleme', 'description': 'Aktivite loglarını görüntüleme'},
        'envanter': {'name': 'Sunucu Envanteri', 'description': 'Sunucu envanter yönetimi'},
        'healthcheck': {'name': 'Healthcheck', 'description': 'Sunucu sağlık kontrolü ve geçmişi'},
        'admin_panel': {'name': 'Admin Panel', 'description': 'Admin yönetim paneli'}
    }

    # GET request - düzenleme formu göster
    return render_template_string("""
    <!doctype html>
    <html>
    <head>
      <meta charset="utf-8">
      <title>Kullanıcı Düzenle</title>
      <style>
        body { font-family: system-ui; margin: 2rem; background: #f5f5f5; }
        .container { max-width: 700px; margin: 0 auto; background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .form-group { margin-bottom: 1rem; }
        label { display: block; margin-bottom: 0.5rem; font-weight: 600; }
        input { width: 100%; padding: 0.75rem; border: 1px solid #ddd; border-radius: 4px; }
        button { background: #007bff; color: white; padding: 0.75rem 1.5rem; border: none; border-radius: 4px; cursor: pointer; }
        button:hover { background: #0056b3; }
        .back-link { display: inline-block; margin-bottom: 1rem; color: #007bff; text-decoration: none; }
        .checkbox-group { display: flex; gap: 1rem; flex-wrap: wrap; }
        .checkbox-item { display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.5rem; }
        .permission-section { background: #f8f9fa; padding: 1rem; border-radius: 4px; margin-bottom: 1rem; }
        .permission-item { background: white; padding: 0.75rem; margin-bottom: 0.5rem; border-radius: 4px; border-left: 4px solid #007bff; }
        .permission-name { font-weight: 600; color: #495057; }
        .permission-desc { font-size: 0.9rem; color: #6c757d; margin-top: 0.25rem; }
        .admin-warning { background: #fff3cd; border: 1px solid #ffeaa7; color: #856404; padding: 0.75rem; border-radius: 4px; margin-bottom: 1rem; }
      </style>
    </head>
    <body>
      <div class="container">
        <a href="{{ url_for('admin_panel') }}" class="back-link">← Admin Panel'e Dön</a>
        <h2>Kullanıcı Düzenle</h2>
        
        {% with messages = get_flashed_messages(with_categories=true) %}
          {% if messages %}
            {% for category, message in messages %}
              <div style="padding: 0.75rem; margin-bottom: 1rem; border-radius: 4px; background: {% if category == 'danger' %}#f8d7da{% else %}#d4edda{% endif %}; color: {% if category == 'danger' %}#721c24{% else %}#155724{% endif %};">
                {{ message }}
              </div>
            {% endfor %}
          {% endif %}
        {% endwith %}
        
        <form method="POST">
          <div class="form-group">
            <label>Kullanıcı Adı</label>
            <input type="text" name="username" value="{{ user.username }}" required>
          </div>
          <div class="form-group">
            <label>Tam Ad</label>
            <input type="text" name="full_name" value="{{ user.full_name }}" required>
          </div>
          <div class="form-group">
            <label>Yeni Şifre (boş bırakılırsa değiştirilmez)</label>
            <input type="password" name="password">
          </div>
          
          {% if user.is_admin %}
          <div class="form-group">
            <div class="admin-warning">
              ⚠️ Bu kullanıcı admin yetkisine sahiptir. Admin yetkisi değiştirilemez.
            </div>
          </div>
          {% endif %}
          
          {% if not user.is_admin %}
          <div class="permission-section">
            <h3>Sayfa Yetkileri</h3>
            <p>Bu kullanıcının hangi sayfalara erişebileceğini belirleyin:</p>
            
            {% for page_key, page_info in page_permissions.items() %}
            {% if page_key != 'admin_panel' %}
            <div class="permission-item">
              <div class="checkbox-item">
                <input type="checkbox" name="{{ page_key }}" id="edit_{{ page_key }}" 
                       {% if user_perms.get(page_key, False) %}checked{% endif %}>
                <label for="edit_{{ page_key }}" class="permission-name">{{ page_info.name }}</label>
              </div>
              <div class="permission-desc">{{ page_info.description }}</div>
            </div>
            {% endif %}
            {% endfor %}
          </div>
          {% else %}
          <div class="permission-section">
            <h3>Sayfa Yetkileri</h3>
            <p>Admin kullanıcıların tüm sayfalara erişim yetkisi vardır.</p>
          </div>
          {% endif %}
          
          <button type="submit">Güncelle</button>
        </form>
      </div>
    </body>
    </html>
    """, user=user, user_perms=user_perms, page_permissions=page_permissions)

@app.route("/admin/delete_user/<int:user_id>", methods=["POST"])
@require_auth("admin_panel")
def admin_delete_user(user_id):
    """Kullanıcıyı sil"""
    if not session.get('is_admin'):
        flash("Bu işlem için admin yetkiniz yok!", "danger")
        return redirect(url_for("admin_panel"))
    
    # Kendi kendini silmeye çalışıyorsa
    if user_id == session.get('user_id'):
        flash("Kendi hesabınızı silemezsiniz!", "danger")
        return redirect(url_for("admin_panel"))
    
    # Silinecek kullanıcıyı bul
    user = db_query("SELECT * FROM users WHERE id = ?", [user_id])
    if not user:
        flash("Kullanıcı bulunamadı!", "danger")
        return redirect(url_for("admin_panel"))
    
    user = user[0]
    
    try:
        # Kullanıcının yetkilerini sil
        db_execute("DELETE FROM user_permissions WHERE user_id = ?", [user_id])
        
        # Kullanıcının aktivite loglarını sil
        db_execute("DELETE FROM activity_logs WHERE user_id = ?", [user_id])
        
        # Kullanıcıyı sil
        db_execute("DELETE FROM users WHERE id = ?", [user_id])
        
        log_activity(session['user_id'], session['username'], 'delete_user', f'Silinmiş kullanıcı: {user["username"]} ({user["full_name"]}) - ID: {user_id}', 'admin_panel')
        flash(f"Kullanıcı '{user['username']}' başarıyla silindi!", "success")
    except Exception as e:
        flash(f"Kullanıcı silinirken hata: {str(e)}", "danger")
    
    return redirect(url_for("admin_panel"))

@app.route("/admin/export_logs_excel")
@require_auth("admin_panel")
def export_logs_excel():
    """Aktivite loglarını Excel olarak export et"""
    from io import BytesIO
    import csv
    
    # Arama parametreleri
    search = request.args.get('search', '').strip()
    filtered = request.args.get('filtered', '').strip()
    
    # Log sorgusu oluştur
    log_query = "SELECT * FROM activity_logs"
    params = []
    
    if search and filtered:
        log_query += " WHERE username LIKE ? OR action LIKE ? OR page_name LIKE ? OR ip_address LIKE ?"
        search_param = f"%{search}%"
        params = [search_param, search_param, search_param, search_param]
    
    log_query += " ORDER BY timestamp DESC"
    
    # Tüm logları al
    logs = db_query(log_query, params)
    
    # CSV oluştur
    from io import StringIO
    
    # StringIO kullan (text için)
    string_output = StringIO()
    
    # CSV writer oluştur
    writer = csv.writer(string_output, delimiter=';', lineterminator='\r\n')
    
    # Başlık satırı
    writer.writerow([
        'Tarih/Saat',
        'Kullanıcı',
        'Aksiyon',
        'Sayfa',
        'IP Adresi',
        'Tarayıcı',
        'Detay'
    ])
    
    # Veri satırları
    for log in logs:
        writer.writerow([
            log['timestamp'],
            log['username'],
            log['action'],
            log['page_name'] or '',
            log['ip_address'],
            log['user_agent'],
            log['action']  # Detay için action kullanıyoruz
        ])
    
    # StringIO'dan string al ve BytesIO'ya encode et
    csv_content = string_output.getvalue()
    output = BytesIO()
    
    # BOM ekle (Excel'de Türkçe karakterler için)
    output.write('\ufeff'.encode('utf-8'))
    output.write(csv_content.encode('utf-8'))
    
    output.seek(0)
    
    # Dosya adı
    filename = "aktivite_loglari"
    if search and filtered:
        filename += f"_filtreli_{search[:20]}"
    filename += ".csv"
    
    # Log export işlemini logla
    log_activity(session['user_id'], session['username'], 'export_logs', 
                f"Excel export - Toplam {len(logs)} kayıt - Arama: '{search}'" if search else f"Excel export - Toplam {len(logs)} kayıt", 'admin_panel')
    
    return send_file(
        output,
        as_attachment=True,
        download_name=filename,
        mimetype='text/csv; charset=utf-8'
    )

@app.route("/admin/manage_permissions/<int:user_id>", methods=["GET", "POST"])
@require_auth("admin_panel")
def admin_manage_permissions(user_id):
    """Kullanıcı yetkilerini yönet"""
    if not session.get('is_admin'):
        flash("Bu işlem için admin yetkiniz yok!", "danger")
        return redirect(url_for("admin_panel"))
    
    # Kullanıcıyı bul
    user = db_query("SELECT * FROM users WHERE id = ?", [user_id])
    if not user:
        flash("Kullanıcı bulunamadı!", "danger")
        return redirect(url_for("admin_panel"))
    
    user = user[0]
    
    # Admin kullanıcıların yetkileri değiştirilebilir (sadece admin kullanıcılar tarafından)
    if user['is_admin'] and not session.get('is_admin'):
        flash("Admin kullanıcıların yetkilerini sadece admin kullanıcılar değiştirebilir!", "danger")
        return redirect(url_for("admin_panel"))
    
    # Sayfa yetkileri tanımları
    page_permissions = {
        'multiquery': {'name': 'Multiquery', 'description': 'PostgreSQL sorgu sayfası'},
        'pg_install': {'name': 'PostgreSQL Installation', 'description': 'PostgreSQL kurulum sayfası'},
        'faydali_linkler': {'name': 'Faydalı Linkler', 'description': 'Faydalı linkler menüsü'},
        'view_logs': {'name': 'Log Görüntüleme', 'description': 'Aktivite loglarını görüntüleme'},
        'envanter': {'name': 'Sunucu Envanteri', 'description': 'Sunucu envanter yönetimi'},
        'admin_panel': {'name': 'Admin Panel', 'description': 'Admin yönetim paneli'}
    }
    
    if request.method == "POST":
        try:
            # Mevcut yetkileri sil
            db_execute("DELETE FROM user_permissions WHERE user_id = ?", [user_id])
            
            # Yeni yetkileri ekle
            for page_name in page_permissions.keys():
                has_permission = bool(request.form.get(page_name))
                db_execute("""
                    INSERT INTO user_permissions (user_id, page_name, can_access)
                    VALUES (?, ?, ?)
                """, [user_id, page_name, has_permission])
            
            log_activity(session['user_id'], session['username'], 'manage_permissions', f'user: {user["username"]}')
            flash("Kullanıcı yetkileri başarıyla güncellendi!", "success")
            return redirect(url_for("admin_panel"))
        except Exception as e:
            flash(f"Yetki güncellenirken hata: {str(e)}", "danger")
    
    # Mevcut yetkileri al
    current_permissions = db_query("SELECT page_name, can_access FROM user_permissions WHERE user_id = ?", [user_id])
    user_perms = {}
    for perm in current_permissions:
        user_perms[perm['page_name']] = perm['can_access']
    
    # GET request - yetki yönetimi formu göster
    return render_template_string("""
    <!doctype html>
    <html>
    <head>
      <meta charset="utf-8">
      <title>Yetki Yönetimi</title>
      <style>
        body { font-family: system-ui; margin: 2rem; background: #f5f5f5; }
        .container { max-width: 600px; margin: 0 auto; background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .form-group { margin-bottom: 1rem; }
        label { display: block; margin-bottom: 0.5rem; font-weight: 600; }
        .checkbox-group { display: flex; align-items: center; gap: 0.5rem; margin-bottom: 1rem; }
        .checkbox-group input[type="checkbox"] { transform: scale(1.2); }
        .permission-item { background: #f8f9fa; padding: 1rem; margin-bottom: 0.5rem; border-radius: 4px; border-left: 4px solid #007bff; }
        .permission-name { font-weight: 600; color: #495057; }
        .permission-desc { font-size: 0.9rem; color: #6c757d; margin-top: 0.25rem; }
        button { background: #007bff; color: white; padding: 0.75rem 1.5rem; border: none; border-radius: 4px; cursor: pointer; }
        button:hover { background: #0056b3; }
        .back-link { display: inline-block; margin-bottom: 1rem; color: #007bff; text-decoration: none; }
        .user-info { background: #e9ecef; padding: 1rem; border-radius: 4px; margin-bottom: 1.5rem; }
      </style>
    </head>
    <body>
      <div class="container">
        <a href="{{ url_for('admin_panel') }}" class="back-link">← Admin Panel'e Dön</a>
        <h2>Yetki Yönetimi</h2>
        
        <div class="user-info">
          <strong>Kullanıcı:</strong> {{ user.username }} ({{ user.full_name }})<br>
          <strong>Durum:</strong> {{ 'Aktif' if user.is_active else 'Pasif' }}<br>
          <strong>Tip:</strong> {{ 'Admin Kullanıcı' if user.is_admin else 'Normal Kullanıcı' }}
          {% if user.is_admin %}
          <br><small style="color: #f59e0b;">⚠️ Admin kullanıcıların yetkileri değiştirilebilir, ancak admin yetkisi korunur.</small>
          {% endif %}
        </div>
        
        {% with messages = get_flashed_messages(with_categories=true) %}
          {% if messages %}
            {% for category, message in messages %}
              <div style="padding: 0.75rem; margin-bottom: 1rem; border-radius: 4px; background: {% if category == 'danger' %}#f8d7da{% else %}#d4edda{% endif %}; color: {% if category == 'danger' %}#721c24{% else %}#155724{% endif %};">
                {{ message }}
              </div>
            {% endfor %}
          {% endif %}
        {% endwith %}
        
        <form method="POST">
          <h3>Sayfa Yetkileri</h3>
          <p>Bu kullanıcının hangi sayfalara erişebileceğini belirleyin:</p>
          
          {% for page_key, page_info in page_permissions.items() %}
          <div class="permission-item">
            <div class="checkbox-group">
              <input type="checkbox" id="{{ page_key }}" name="{{ page_key }}" 
                     {% if user_perms.get(page_key, False) %}checked{% endif %}>
              <label for="{{ page_key }}" class="permission-name">{{ page_info.name }}</label>
            </div>
            <div class="permission-desc">{{ page_info.description }}</div>
          </div>
          {% endfor %}
          
          <button type="submit">Yetkileri Güncelle</button>
        </form>
      </div>
    </body>
    </html>
    """, user=user, page_permissions=page_permissions, user_perms=user_perms)

# Sunucuları listeleme template'i
TEMPLATE_SUNUCULARI_LISTELE = r"""
<!doctype html>
<html lang="tr">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Sunucuları Listele - PostgreSQL Management System</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
      /* Theme variables */
      :root {
        --bg: #f8fafc; --panel: #ffffff; --muted: #64748b; --txt: #1e293b; --brand: #3b82f6; --accent: #06b6d4; --ring: rgba(59,130,246,.35);
        --drop: #ffffff; --hover: #f1f5f9;
      }
      
      /* Dark mode variables */
      [data-theme="dark"] {
        --bg: #0f1216; --panel: #171b21; --muted: #9aa5b1; --txt: #eef2f6; --brand: #50b0ff; --accent: #7cf; --ring: rgba(80,176,255,.35);
        --drop: #0f1216; --hover: #212833;
      }
      
      body { 
        padding-top: 20px; 
        background: var(--bg); 
        color: var(--txt);
        font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif;
      }
      
      [data-theme="dark"] body { background: linear-gradient(180deg, #0c0f13, #0f1216); }
      [data-theme="light"] body { background: linear-gradient(180deg, #f1f5f9, #f8fafc); }
      
      .container-lg { background: var(--panel); border-radius: 1rem; padding: 2rem; margin-top: 1rem; border: 1px solid; max-width: 1200px; }
      [data-theme="dark"] .container-lg { border-color: #242b37; }
      [data-theme="light"] .container-lg { border-color: #e2e8f0; }
      
      .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 2rem; padding-bottom: 1rem; border-bottom: 1px solid; }
      [data-theme="dark"] .header { border-color: #242b37; }
      [data-theme="light"] .header { border-color: #e2e8f0; }
      
      .header h1 { margin: 0; color: var(--txt); font-weight: 700; font-size: 2rem; }
      
      .card { background: var(--panel); border: 1px solid; border-radius: 0.75rem; padding: 1.5rem; margin-bottom: 1.5rem; }
      [data-theme="dark"] .card { border-color: #242b37; }
      [data-theme="light"] .card { border-color: #e2e8f0; }
      
      .card h3 { margin: 0 0 1rem 0; color: var(--txt); font-weight: 600; }
      .card h4 { margin: 0 0 1rem 0; color: var(--txt); font-weight: 600; }
      
      .table { color: var(--txt); background: var(--panel); }
      .table-striped > tbody > tr:nth-of-type(odd) > td { background: var(--hover); }
      
      .status-success { background: rgba(16, 185, 129, 0.1); color: #10b981; border: 1px solid rgba(16, 185, 129, 0.2); padding: 0.25rem 0.5rem; border-radius: 0.25rem; font-weight: 600; }
      .status-danger { background: rgba(239, 68, 68, 0.1); color: #ef4444; border: 1px solid rgba(239, 68, 68, 0.2); padding: 0.25rem 0.5rem; border-radius: 0.25rem; font-weight: 600; }
      .status-warning { background: rgba(245, 158, 11, 0.1); color: #f59e0b; border: 1px solid rgba(245, 158, 11, 0.2); padding: 0.25rem 0.5rem; border-radius: 0.25rem; font-weight: 600; }
      
      .server-card { margin-bottom: 1.5rem; }
      .server-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem; }
      .server-title { font-size: 1.25rem; font-weight: 600; color: var(--txt); }
      .server-date { font-size: 0.875rem; color: var(--muted); }
      
      /* Disk bilgileri stilleri */
      .disk-info-item { 
        margin-bottom: 0.5rem; 
        padding: 0.5rem; 
        background: var(--hover); 
        border-radius: 0.25rem; 
        border: 1px solid transparent;
      }
      [data-theme="dark"] .disk-info-item { border-color: #242b37; }
      [data-theme="light"] .disk-info-item { border-color: #e2e8f0; }
      
      .disk-device { font-weight: 600; color: var(--txt); }
      .disk-mount { color: var(--muted); font-style: italic; }
      .disk-details { font-size: 0.875rem; color: var(--txt); margin-top: 0.25rem; }
      
      .text-muted { color: var(--muted) !important; }
      
      /* Theme Toggle Button */
      #themeToggle { all: unset; cursor: pointer; padding: 0.5rem; border-radius: 0.5rem; display: flex; align-items: center; justify-content: center; background: var(--hover); border: 1px solid transparent; }
      #themeToggle:hover { background: var(--hover); border-color: var(--brand); }
      [data-theme="dark"] #themeToggle:hover { border-color: #50b0ff; }
      [data-theme="light"] #themeToggle:hover { border-color: #3b82f6; }
    </style>
  </head>
  <body>
    <div class="container-lg">
      <div class="header">
        <h1>📋 Sunucuları Listele</h1>
        <div style="display: flex; align-items: center; gap: 1rem;">
          <a href="/envanter" class="btn btn-outline-secondary" style="padding: 0.5rem 1rem; font-size: 0.9rem;">← Envanter</a>
          <button id="themeToggle" title="Dark/Light Mode Toggle">
            <span id="themeIcon" style="font-size: 1.2rem;">🌙</span>
          </button>
        </div>
      </div>
      
      {% with messages = get_flashed_messages(with_categories=true) %}
        {% if messages %}
          {% for category, message in messages %}
            <div class="alert alert-{{ category }}">
              {{ message }}
            </div>
          {% endfor %}
        {% endif %}
      {% endwith %}
      
      {% if servers %}
        <div class="card">
          <h3>📊 Kayıtlı Sunucular ({{ servers|length }} adet)</h3>
          
          {% for server in servers %}
            <div class="server-card">
              <div class="server-header">
                <div class="server-title">🖥️ {{ server.hostname }}</div>
                <div class="server-date">{{ server.created_at }}</div>
              </div>
              
              <div class="table-responsive">
                <table class="table table-striped">
                  <tbody>
                    <tr>
                      <td style="width: 30%;"><strong>Sunucu IP Adresi</strong></td>
                      <td>{{ server.ip }}</td>
                    </tr>
                    <tr>
                      <td><strong>SSH Bilgileri</strong></td>
                      <td>Port: {{ server.ssh_port }} | Kullanıcı: {{ server.ssh_user }}</td>
                    </tr>
                    <tr>
                      <td><strong>İşletim Sistemi</strong></td>
                      <td>{{ server.os_info }}</td>
                    </tr>
                    <tr>
                      <td><strong>CPU Bilgisi</strong></td>
                      <td>{{ server.cpu_info }}</td>
                    </tr>
                    <tr>
                      <td><strong>CPU Core Sayısı</strong></td>
                      <td>{{ server.cpu_cores }}</td>
                    </tr>
                    <tr>
                      <td><strong>Toplam RAM</strong></td>
                      <td>{{ server.ram_total }}</td>
                    </tr>
                    <tr>
                      <td><strong>Disk Bilgileri</strong></td>
                      <td>
                        {% if server.disks %}
                          {% for disk in server.disks %}
                            <div class="disk-info-item">
                              <div class="disk-device">{{ disk.device }}</div>
                              <div class="disk-mount">{{ disk.mount }}</div>
                              <div class="disk-details">
                                {{ disk.size }} toplam | {{ disk.used }} kullanılan | {{ disk.available }} boş
                                <span class="status-{{ 'warning' if disk.percent_num >= 80 else 'success' }}" style="margin-left: 0.5rem;">
                                  {{ disk.percent }}
                                </span>
                              </div>
                            </div>
                          {% endfor %}
                        {% else %}
                          Disk bilgisi yok
                        {% endif %}
                      </td>
                    </tr>
                    <tr>
                      <td><strong>Sistem Uptime</strong></td>
                      <td>{{ server.uptime }}</td>
                    </tr>
                    <tr>
                      <td><strong>PostgreSQL Durumu</strong></td>
                      <td>
                        {% if server.postgresql_status == 'Var' %}
                          <span class="status-success">✓ Var</span>
                        {% else %}
                          <span class="status-danger">✗ Yok</span>
                        {% endif %}
                      </td>
                    </tr>
                    {% if server.postgresql_status == 'Var' %}
                    <tr>
                      <td><strong>PostgreSQL Versiyonu</strong></td>
                      <td>{{ server.postgresql_version }}</td>
                    </tr>
                    <tr>
                      <td><strong>PostgreSQL Replication</strong></td>
                      <td>
                        {% if server.postgresql_replication == 'Var' %}
                          <span class="status-success">✓ Var</span>
                        {% else %}
                          <span class="status-danger">✗ Yok</span>
                        {% endif %}
                      </td>
                    </tr>
                    {% endif %}
                    <tr>
                      <td><strong>pgBackRest Durumu</strong></td>
                      <td>
                        {% if server.pgbackrest_status == 'Var' %}
                          <span class="status-success">✓ Var</span>
                        {% else %}
                          <span class="status-danger">✗ Yok</span>
                        {% endif %}
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>
          {% endfor %}
          
          <div class="d-grid gap-2 d-md-flex justify-content-md-end mt-4">
            <button class="btn btn-success" onclick="exportServersToExcel()">📊 Excel'e Aktar</button>
          </div>
        </div>
      {% else %}
        <div class="card">
          <h3>📋 Kayıtlı Sunucu Yok</h3>
          <p class="text-muted">Henüz hiç sunucu eklenmemiş. Manuel veya toplu sunucu ekleme ile sunucu bilgilerini toplayabilirsiniz.</p>
          <div style="display: flex; gap: 1rem;">
            <a href="/manuel-sunucu-ekle" class="btn btn-primary">➕ Manuel Sunucu Ekle</a>
            <a href="/toplu-sunucu-ekle" class="btn btn-warning">📦 Toplu Sunucu Ekle</a>
          </div>
        </div>
      {% endif %}
    </div>
    
    <script>
    // Dark Mode Toggle
    function initTheme() {
      const savedTheme = localStorage.getItem('theme') || 'dark';
      const prefersDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
      const theme = savedTheme === 'dark' || (savedTheme === 'auto' && prefersDark) ? 'dark' : 'light';
      
      document.documentElement.setAttribute('data-theme', theme);
      
      const themeIcon = document.getElementById('themeIcon');
      if (themeIcon) {
        themeIcon.textContent = theme === 'dark' ? '🌙' : '☀️';
      }
      
      localStorage.setItem('theme', theme);
    }

    function toggleTheme() {
      const currentTheme = document.documentElement.getAttribute('data-theme');
      const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
      
      document.documentElement.setAttribute('data-theme', newTheme);
      
      const themeIcon = document.getElementById('themeIcon');
      if (themeIcon) {
        themeIcon.textContent = newTheme === 'dark' ? '🌙' : '☀️';
      }
      
      localStorage.setItem('theme', newTheme);
    }

    // Initialize theme on page load
    document.addEventListener('DOMContentLoaded', function() {
      initTheme();

      // Add click event to theme toggle
      const themeToggle = document.getElementById('themeToggle');
      if (themeToggle) {
        themeToggle.addEventListener('click', toggleTheme);
      }
    });
    
    // Excel export function
    function exportServersToExcel() {
      window.location.href = '/sunucu-excel-export';
    }
    </script>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
  </body>
</html>
"""


@app.route("/test-server-connection")
@require_auth("multiquery")
def test_server_connection():
    server_ip = request.args.get('ip', '192.168.1.3')
    
    # Envanter sunucusunu bul
    inventory_data = db_query("""
        SELECT hostname, ip, ssh_port, ssh_user, ssh_password, postgresql_status, postgresql_version
        FROM sunucu_envanteri 
        WHERE ip = ?
    """, (server_ip,))
    
    if not inventory_data:
        return f"Sunucu bulunamadı: {server_ip}"
    
    inv_server = inventory_data[0]
    decrypted_password = decrypt_password(inv_server['ssh_password']) if inv_server['ssh_password'] else ''
    
    result = f"<h3>Sunucu Test Raporu: {inv_server['hostname']} ({server_ip})</h3>"
    
    # SSH bağlantı testi
    try:
        import paramiko
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname=inv_server['ip'], port=int(inv_server['ssh_port']), 
                   username=inv_server['ssh_user'], password=decrypted_password, timeout=10)
        
        result += "<h4>✅ SSH Bağlantısı: BAŞARILI</h4>"
        
        # PostgreSQL servis durumu
        stdin, stdout, stderr = ssh.exec_command("systemctl status postgresql")
        service_output = stdout.read().decode()
        result += f"<h4>PostgreSQL Servis Durumu:</h4><pre>{service_output}</pre>"
        
        # PostgreSQL process'leri
        stdin, stdout, stderr = ssh.exec_command("ps aux | grep postgres | grep -v grep")
        process_output = stdout.read().decode()
        result += f"<h4>PostgreSQL Process'leri:</h4><pre>{process_output}</pre>"
        
        # Dinlenen portlar
        stdin, stdout, stderr = ssh.exec_command("netstat -tlnp | grep postgres")
        netstat_output = stdout.read().decode()
        result += f"<h4>PostgreSQL Dinlenen Portlar (netstat):</h4><pre>{netstat_output}</pre>"
        
        stdin, stdout, stderr = ssh.exec_command("ss -tlnp | grep postgres")
        ss_output = stdout.read().decode()
        result += f"<h4>PostgreSQL Dinlenen Portlar (ss):</h4><pre>{ss_output}</pre>"
        
        # PostgreSQL konfigürasyonu
        stdin, stdout, stderr = ssh.exec_command("sudo -u postgres psql -t -c \"SHOW port;\" 2>/dev/null")
        port_output = stdout.read().decode().strip()
        result += f"<h4>PostgreSQL Konfigürasyon Port:</h4><pre>{port_output}</pre>"
        
        stdin, stdout, stderr = ssh.exec_command("sudo -u postgres psql -t -c \"SHOW listen_addresses;\" 2>/dev/null")
        listen_output = stdout.read().decode().strip()
        result += f"<h4>PostgreSQL Listen Addresses:</h4><pre>{listen_output}</pre>"
        
        # PostgreSQL konfigürasyon dosyası
        stdin, stdout, stderr = ssh.exec_command("find /etc/postgresql -name 'postgresql.conf' 2>/dev/null | head -1")
        config_file = stdout.read().decode().strip()
        if config_file:
            stdin, stdout, stderr = ssh.exec_command(f"grep -E '^(port|listen_addresses)' {config_file} 2>/dev/null")
            config_output = stdout.read().decode()
            result += f"<h4>PostgreSQL Konfigürasyon Dosyası ({config_file}):</h4><pre>{config_output}</pre>"
        
        ssh.close()
        
    except Exception as e:
        result += f"<h4>❌ SSH Bağlantı Hatası:</h4><pre>{str(e)}</pre>"
    
    # PostgreSQL bağlantı testleri
    result += "<h4>PostgreSQL Bağlantı Testleri:</h4>"
    test_ports = [5432, 5433, 5434, 5435, 5436, 5437, 5438, 5439, 5440]
    
    for test_port in test_ports:
        try:
            import psycopg2
            test_conn = psycopg2.connect(
                host=server_ip,
                port=test_port,
                database='postgres',
                user='postgres',
                password=decrypted_password,
                connect_timeout=3
            )
            test_conn.close()
            result += f"✅ Port {test_port}: BAŞARILI<br>"
            break
        except Exception as e:
            result += f"❌ Port {test_port}: {str(e)}<br>"
    
    return result


# Healthcheck silme endpoint'leri
@app.route("/api/healthcheck/delete/<int:record_id>", methods=["DELETE"])
@require_auth("healthcheck")
def delete_healthcheck_record(record_id):
    """Tek bir healthcheck kaydını siler"""
    try:
        # Kaydın var olup olmadığını kontrol et
        record = db_query("SELECT * FROM healthcheck_results WHERE id = ?", (record_id,))
        
        if not record:
            return jsonify({"error": "Kayıt bulunamadı"}), 404
        
        # Kaydı sil
        db_execute("DELETE FROM healthcheck_results WHERE id = ?", (record_id,))
        
        # Log kaydı
        log_activity(
            session.get('user_id'),
            session.get('username'),
            'healthcheck_delete',
            f"Healthcheck kaydı silindi: ID={record_id}, Hostname={record[0]['hostname']}",
            'healthcheck'
        )
        
        return jsonify({"success": True, "message": "Kayıt başarıyla silindi"}), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/healthcheck/delete-multiple", methods=["POST"])
@require_auth("healthcheck")
def delete_multiple_healthcheck_records():
    """Birden fazla healthcheck kaydını siler"""
    try:
        data = request.get_json()
        ids = data.get('ids', [])
        
        if not ids:
            return jsonify({"error": "Silinecek kayıt seçilmedi"}), 400
        
        # IDs listesini integer'a çevir
        try:
            ids = [int(id_) for id_ in ids]
        except ValueError:
            return jsonify({"error": "Geçersiz ID formatı"}), 400
        
        # Kayıtları sil
        placeholders = ','.join(['?' for _ in ids])
        query = f"DELETE FROM healthcheck_results WHERE id IN ({placeholders})"
        db_execute(query, tuple(ids))
        
        # Log kaydı
        log_activity(
            session.get('user_id'),
            session.get('username'),
            'healthcheck_delete_multiple',
            f"{len(ids)} adet healthcheck kaydı silindi: IDs={ids}",
            'healthcheck'
        )
        
        return jsonify({
            "success": True,
            "message": f"{len(ids)} kayıt başarıyla silindi",
            "deleted_count": len(ids)
        }), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# Admin Dashboard Stats API
@app.route("/api/admin/dashboard-stats", methods=["GET"])
@require_auth("admin_panel")
def get_admin_dashboard_stats():
    """Admin dashboard için detaylı istatistikler"""
    try:
        # Toplam sunucu sayısı
        total_servers_query = db_query("SELECT COUNT(*) as count FROM sunucu_envanteri")
        total_servers = total_servers_query[0]['count'] if total_servers_query else 0
        
        # PostgreSQL sunucu sayısı
        pg_servers_query = db_query("SELECT COUNT(*) as count FROM sunucu_envanteri WHERE postgresql_status = 'Var'")
        pg_servers = pg_servers_query[0]['count'] if pg_servers_query else 0
        
        # Toplam kullanıcı sayısı
        total_users_query = db_query("SELECT COUNT(*) as count FROM users")
        total_users = total_users_query[0]['count'] if total_users_query else 0
        
        # Aktif kullanıcı sayısı
        active_users_query = db_query("SELECT COUNT(*) as count FROM users WHERE is_active = 1")
        active_users = active_users_query[0]['count'] if active_users_query else 0
        
        # Bugünkü sorgu sayısı
        today_queries_query = db_query("""
            SELECT COUNT(*) as count FROM activity_logs 
            WHERE action LIKE '%SQL%' AND DATE(timestamp) = DATE('now')
        """)
        today_queries = today_queries_query[0]['count'] if today_queries_query else 0
        
        # Bu haftaki sorgu sayısı
        weekly_queries_query = db_query("""
            SELECT COUNT(*) as count FROM activity_logs 
            WHERE action LIKE '%SQL%' AND timestamp >= datetime('now', '-7 days')
        """)
        weekly_queries = weekly_queries_query[0]['count'] if weekly_queries_query else 0
        
        # Toplam healthcheck sayısı
        total_healthchecks_query = db_query("SELECT COUNT(*) as count FROM healthcheck_results")
        total_healthchecks = total_healthchecks_query[0]['count'] if total_healthchecks_query else 0
        
        # Bugünkü healthcheck sayısı
        today_healthchecks_query = db_query("""
            SELECT COUNT(*) as count FROM healthcheck_results 
            WHERE DATE(created_at) = DATE('now')
        """)
        today_healthchecks = today_healthchecks_query[0]['count'] if today_healthchecks_query else 0
        
        # Son 24 saatteki başarısız healthcheck sayısı
        failed_healthchecks_query = db_query("""
            SELECT COUNT(*) as count FROM healthcheck_results 
            WHERE status != 'success' AND created_at >= datetime('now', '-1 day')
        """)
        failed_healthchecks = failed_healthchecks_query[0]['count'] if failed_healthchecks_query else 0
        
        # Son 10 aktivite
        recent_activities = db_query("""
            SELECT username, action, page_name, 
                   strftime('%d.%m.%Y %H:%M', timestamp) as timestamp
            FROM activity_logs 
            ORDER BY timestamp DESC 
            LIMIT 10
        """)
        
        # PostgreSQL sunucuları
        postgresql_servers = db_query("""
            SELECT hostname, ip, postgresql_version, postgresql_status
            FROM sunucu_envanteri 
            WHERE postgresql_status = 'Var'
            ORDER BY hostname
        """)
        
        # En aktif kullanıcılar (son 7 gün)
        top_users = db_query("""
            SELECT u.username, u.full_name, COUNT(a.id) as activity_count
            FROM users u
            LEFT JOIN activity_logs a ON u.id = a.user_id 
                AND a.timestamp >= datetime('now', '-7 days')
            WHERE u.is_active = 1
            GROUP BY u.id, u.username, u.full_name
            ORDER BY activity_count DESC
            LIMIT 5
        """)
        
        # Kritik uyarılar
        critical_alerts = []
        
        # %90 üzeri disk doluluk kontrolü
        critical_servers = db_query("""
            SELECT hostname, ip, disks 
            FROM sunucu_envanteri 
            WHERE disks IS NOT NULL AND disks != '[]'
        """)
        
        import json
        for server in critical_servers:
            try:
                disks = json.loads(server['disks'])
                for disk in disks:
                    percent = int(disk.get('percent', '0').replace('%', ''))
                    if percent >= 90:
                        critical_alerts.append({
                            'severity': 'critical',
                            'title': f"Kritik Disk Doluluk: {server['hostname']}",
                            'message': f"{disk['device']} ({disk['mount']}) - {disk['percent']} dolu!",
                            'action': '/envanter'
                        })
            except:
                pass
        
        # Başarısız healthcheck kontrolü
        if failed_healthchecks > 0:
            critical_alerts.append({
                'severity': 'warning',
                'title': f"{failed_healthchecks} Başarısız Healthcheck",
                'message': f"Son 24 saatte {failed_healthchecks} healthcheck başarısız oldu.",
                'action': '/healthcheck'
            })
        
        # Geçen haftaki veriler (karşılaştırma için)
        last_week_queries = db_query("""
            SELECT COUNT(*) as count FROM activity_logs 
            WHERE action LIKE '%SQL%' 
            AND timestamp >= datetime('now', '-14 days')
            AND timestamp < datetime('now', '-7 days')
        """)
        last_week_queries_count = last_week_queries[0]['count'] if last_week_queries else 0
        
        last_week_healthchecks = db_query("""
            SELECT COUNT(*) as count FROM healthcheck_results 
            WHERE created_at >= datetime('now', '-14 days')
            AND created_at < datetime('now', '-7 days')
        """)
        last_week_healthchecks_count = last_week_healthchecks[0]['count'] if last_week_healthchecks else 0
        
        last_week_logins = db_query("""
            SELECT COUNT(*) as count FROM activity_logs 
            WHERE action LIKE '%Giriş%' 
            AND timestamp >= datetime('now', '-14 days')
            AND timestamp < datetime('now', '-7 days')
        """)
        last_week_logins_count = last_week_logins[0]['count'] if last_week_logins else 0
        
        # Bu haftaki veriler
        this_week_logins = db_query("""
            SELECT COUNT(*) as count FROM activity_logs 
            WHERE action LIKE '%Giriş%' AND timestamp >= datetime('now', '-7 days')
        """)
        this_week_logins_count = this_week_logins[0]['count'] if this_week_logins else 0
        
        this_week_healthchecks = db_query("""
            SELECT COUNT(*) as count FROM healthcheck_results 
            WHERE created_at >= datetime('now', '-7 days')
        """)
        this_week_healthchecks_count = this_week_healthchecks[0]['count'] if this_week_healthchecks else 0
        
        # Yüzde değişim hesapla
        def calc_change(current, previous):
            if previous == 0:
                return 0
            return round(((current - previous) / previous) * 100)
        
        # Son 7 günün günlük aktiviteleri (grafik için)
        daily_activities = db_query("""
            SELECT DATE(timestamp) as day, COUNT(*) as count
            FROM activity_logs
            WHERE timestamp >= datetime('now', '-7 days')
            GROUP BY DATE(timestamp)
            ORDER BY day
        """)
        
        # Günleri formatla
        for activity in daily_activities:
            day_str = activity['day']
            # YYYY-MM-DD formatını DD/MM'ye çevir
            if day_str:
                parts = day_str.split('-')
                if len(parts) == 3:
                    activity['day'] = f"{parts[2]}/{parts[1]}"
        
        # Son 5 giriş
        recent_logins = db_query("""
            SELECT u.username, u.full_name, a.ip_address,
                   strftime('%d.%m.%Y %H:%M', a.timestamp) as timestamp
            FROM activity_logs a
            JOIN users u ON a.user_id = u.id
            WHERE a.action LIKE '%Giriş%'
            ORDER BY a.timestamp DESC
            LIMIT 5
        """)
        
        # Database metrikleri
        import os
        db_size = 0
        db_size_mb = "0 MB"
        try:
            db_path = SQLITE_PATH
            if os.path.exists(db_path):
                db_size = os.path.getsize(db_path)
                if db_size < 1024:
                    db_size_mb = f"{db_size} B"
                elif db_size < 1024 * 1024:
                    db_size_mb = f"{db_size / 1024:.2f} KB"
                else:
                    db_size_mb = f"{db_size / (1024 * 1024):.2f} MB"
        except:
            pass
        
        # Toplam kayıt sayısı
        total_records = db_query("""
            SELECT 
                (SELECT COUNT(*) FROM sunucu_envanteri) +
                (SELECT COUNT(*) FROM healthcheck_results) +
                (SELECT COUNT(*) FROM activity_logs) +
                (SELECT COUNT(*) FROM users) as total
        """)
        total_records_count = total_records[0]['total'] if total_records else 0
        
        # Healthcheck başarı oranı
        success_healthchecks = db_query("SELECT COUNT(*) as count FROM healthcheck_results WHERE status = 'success'")
        success_count = success_healthchecks[0]['count'] if success_healthchecks else 0
        success_rate = round((success_count / total_healthchecks * 100)) if total_healthchecks > 0 else 0
        
        # Sistem uptime (uygulama ne zaman başlatıldı?)
        from datetime import datetime
        import time
        uptime_seconds = time.time() - os.path.getctime(db_path) if os.path.exists(db_path) else 0
        uptime_days = int(uptime_seconds / 86400)
        uptime_hours = int((uptime_seconds % 86400) / 3600)
        system_uptime = f"{uptime_days} gün {uptime_hours} saat"
        
        return jsonify({
            "totalServers": total_servers,
            "pgServers": pg_servers,
            "totalUsers": total_users,
            "activeUsers": active_users,
            "todayQueries": today_queries,
            "weeklyQueries": weekly_queries,
            "totalHealthchecks": total_healthchecks,
            "todayHealthchecks": today_healthchecks,
            "failedHealthchecks": failed_healthchecks,
            "recentActivities": recent_activities,
            "postgresqlServers": postgresql_servers,
            "topUsers": top_users,
            "criticalAlerts": critical_alerts,
            "weeklyComparison": {
                "weeklyQueries": weekly_queries,
                "weeklyHealthchecks": this_week_healthchecks_count,
                "weeklyLogins": this_week_logins_count,
                "serversAdded": 0,
                "queryChange": calc_change(weekly_queries, last_week_queries_count),
                "healthcheckChange": calc_change(this_week_healthchecks_count, last_week_healthchecks_count),
                "loginChange": calc_change(this_week_logins_count, last_week_logins_count)
            },
            "dailyActivities": daily_activities,
            "recentLogins": recent_logins,
            "databaseMetrics": {
                "dbSize": db_size_mb,
                "totalRecords": total_records_count,
                "healthcheckSuccessRate": success_rate,
                "systemUptime": system_uptime
            }
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# Eski API endpoint (geriye uyumluluk için)
@app.route("/api/stats", methods=["GET"])
def get_basic_stats():
    """Basit istatistikler (geriye uyumluluk)"""
    try:
        total_servers_query = db_query("SELECT COUNT(*) as count FROM sunucu_envanteri")
        total_servers = total_servers_query[0]['count'] if total_servers_query else 0
        
        total_users_query = db_query("SELECT COUNT(*) as count FROM users WHERE is_active = 1")
        total_users = total_users_query[0]['count'] if total_users_query else 0
        
        today_queries_query = db_query("""
            SELECT COUNT(*) as count FROM activity_logs 
            WHERE action LIKE '%SQL%' AND DATE(timestamp) = DATE('now')
        """)
        today_queries = today_queries_query[0]['count'] if today_queries_query else 0
        
        return jsonify({
            "servers": total_servers,
            "users": total_users,
            "todayQueries": today_queries
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    init_db()
    init_sunucu_envanteri_table()
    init_healthcheck_table()
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=True)
