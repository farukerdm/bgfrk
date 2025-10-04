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

# --- META DB: SQLite dosya yolu ---
SQLITE_PATH = os.environ.get("PG_UI_META_SQLITE", "mq_meta.db")

MAX_ROWS = int(os.environ.get("PG_UI_MAX_ROWS", "1000"))
WORKERS = int(os.environ.get("PG_UI_WORKERS", "16"))
STMT_TIMEOUT_MS = int(os.environ.get("PG_UI_TIMEOUT_MS", "15000"))

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", "dev-secret-change-me")
app.config['JSON_AS_ASCII'] = False
app.config['TEMPLATES_AUTO_RELOAD'] = True

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
        pages = ['multiquery', 'pg_install', 'admin_panel', 'faydali_linkler', 'view_logs']
        for page in pages:
            con.execute("""
                INSERT INTO user_permissions (user_id, page_name, can_access) 
                VALUES (?, ?, 1)
            """, [admin_id, page])
        
        con.commit()

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
    except Exception as e:
        print(f"Sunucu envanteri tablosu oluşturulurken hata: {e}")

def save_sunucu_bilgileri(server_info):
    """Sunucu bilgilerini veritabanına kaydet (varsa güncelle, yoksa ekle)"""
    try:
        # Disks bilgisini JSON string'e çevir
        import json
        disks_json = json.dumps(server_info.get('disks', []))
        
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
                        hostname = ?, ip = ?, ssh_port = ?, ssh_user = ?, 
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
                (hostname, ip, ssh_port, ssh_user, os_info, cpu_info, cpu_cores, 
                 ram_total, disks, uptime, postgresql_status, postgresql_version, 
                 postgresql_replication, pgbackrest_status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                server_info.get('hostname', ''),
                server_info.get('ip', ''),
                server_info.get('ssh_port', 22),
                server_info.get('ssh_user', ''),
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
        'system_stop': '⏹️ Sistem durduruldu'
    }
    
    # Detaylı mesaj oluştur
    action_message = action_messages.get(action, action)
    
    # Detaylı log mesajı
    log_details = f"{action_message}"
    if details:
        log_details += f" - {details}"
    
    # IP adresini kısalt (güvenlik için)
    short_ip = ip_address[:15] + "..." if len(ip_address) > 15 else ip_address
    
    # User agent'ı kısalt
    short_ua = user_agent[:50] + "..." if len(user_agent) > 50 else user_agent
    
    try:
        db_execute("""
            INSERT INTO activity_logs (user_id, username, action, details, page_name, ip_address, user_agent, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))
        """, [user_id, username, action_message, details, page_name, short_ip, short_ua])
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
    details = f"Sorgu: '{query_preview}' | Sunucular: {server_list} | Başarılı: {success_count}/{len(results)} | Toplam satır: {total_rows}"
    if error_count > 0:
        details += f" | Hatalı: {error_count}"
    
    # IP ve User Agent'ı kısalt
    short_ip = ip_address[:15] + "..." if len(ip_address) > 15 else ip_address
    short_ua = user_agent[:50] + "..." if len(user_agent) > 50 else user_agent
    
    try:
        db_execute("""
            INSERT INTO activity_logs (user_id, username, action, details, page_name, ip_address, user_agent, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))
        """, [user_id, username, "📊 SQL sorgusu çalıştırdı", details, page_name, short_ip, short_ua])
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
        
        # CPU bilgisi
        try:
            stdin, stdout, stderr = ssh.exec_command("cat /proc/cpuinfo | grep 'model name' | head -1 | cut -d':' -f2 | xargs")
            cpu_info = stdout.read().decode().strip()
            if cpu_info:
                server_info['cpu_info'] = cpu_info
        except:
            pass
        
        # CPU core sayısı
        try:
            stdin, stdout, stderr = ssh.exec_command("nproc")
            cpu_cores = stdout.read().decode().strip()
            if cpu_cores:
                server_info['cpu_cores'] = f"{cpu_cores} cores"
        except:
            pass
        
        # RAM bilgisi
        try:
            stdin, stdout, stderr = ssh.exec_command("free -h | grep 'Mem:' | awk '{print $2}'")
            ram_info = stdout.read().decode().strip()
            if ram_info:
                server_info['ram_total'] = ram_info
        except:
            pass
        
        # Disk bilgisi - daha detaylı format ve debug
        try:
            # Önce tüm diskleri al
            stdin, stdout, stderr = ssh.exec_command("df -h | grep -v 'tmpfs\\|udev\\|Filesystem' | awk '{print $1\"|\"$2\"|\"$3\"|\"$4\"|\"$5\"|\"$6}' | head -10")
            disk_info = stdout.read().decode().strip()
            stderr_output = stderr.read().decode().strip()
            
            print(f"Disk komut çıktısı: {disk_info}")
            if stderr_output:
                print(f"Disk komut hatası: {stderr_output}")
            
            if disk_info:
                disks = []
                for line in disk_info.split('\n'):
                    if line.strip():
                        parts = line.split('|')
                        print(f"Disk satırı parse ediliyor: {line} -> {parts}")
                        if len(parts) >= 6:
                            device = parts[0].strip()
                            size = parts[1].strip()
                            used = parts[2].strip()
                            available = parts[3].strip()
                            percent = parts[4].strip()
                            mount = parts[5].strip()
                            
                            print(f"Disk bulundu: {device} -> {mount} ({percent})")
                            
                            # Tüm fiziksel diskleri ekle (filtreleme kaldırıldı)
                            if device and device != '' and mount and mount != '':
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
                    # Yöntem 1: PostgreSQL server versiyonu (en güvenilir)
                    stdin, stdout, stderr = ssh.exec_command("sudo -u postgres psql -c 'SELECT version();' 2>/dev/null | grep PostgreSQL")
                    pg_version = stdout.read().decode().strip()
                    
                    # Yöntem 2: Eğer yukarısı çalışmazsa, postgres server binary versiyonu
                    if not pg_version or 'PostgreSQL' not in pg_version:
                        stdin, stdout, stderr = ssh.exec_command("sudo -u postgres postgres --version 2>/dev/null")
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
                    stdin, stdout, stderr = ssh.exec_command("sudo -u postgres psql -c 'SELECT client_addr FROM pg_stat_replication LIMIT 1;' 2>/dev/null | grep -v 'client_addr\\|^-\\|^$'")
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
(function(){
  const saved = localStorage.getItem('theme');
  const prefersDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
  const theme = saved || (prefersDark ? 'dark' : 'light');
  document.documentElement.setAttribute('data-bs-theme', theme);
  window.addEventListener('DOMContentLoaded', function(){
    const toggle = document.getElementById('themeToggle');
    if (toggle){
      toggle.checked = (document.documentElement.getAttribute('data-bs-theme') === 'dark');
      toggle.addEventListener('change', function(){
        const t = this.checked ? 'dark' : 'light';
        document.documentElement.setAttribute('data-bs-theme', t);
        localStorage.setItem('theme', t);
      });
    }
  });
})();
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
      <!-- İstatistik Kartları -->
      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 2rem;">
        <!-- Sunucu Sayısı -->
        <div class="stat-card clickable-stat" onclick="showServersModal()">
          <div class="stat-icon">🖥️</div>
          <div class="stat-content">
            <div class="stat-number" id="adminServers">0</div>
            <div class="stat-label">Kayıtlı Sunucu</div>
          </div>
        </div>
        
        <!-- Toplam Kullanıcı -->
        <div class="stat-card clickable-stat" onclick="showUsersModal()">
          <div class="stat-icon">👥</div>
          <div class="stat-content">
            <div class="stat-number" id="adminUsers">0</div>
            <div class="stat-label">Aktif Kullanıcı</div>
          </div>
        </div>
        
        <!-- Bugünkü Sorgular -->
        <div class="stat-card clickable-stat" onclick="showQueriesModal()">
          <div class="stat-icon">📊</div>
          <div class="stat-content">
            <div class="stat-number" id="adminTodayQueries">0</div>
            <div class="stat-label">Bugünkü Sorgular</div>
          </div>
        </div>
        
        <!-- Sistem Durumu -->
        <div class="stat-card">
          <div class="stat-icon">✅</div>
          <div class="stat-content">
            <div class="stat-number" style="color: #10b981;">Online</div>
            <div class="stat-label">Sistem Durumu</div>
          </div>
        </div>
      </div>
      
      <!-- Hızlı Erişim Kartları -->
      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 1rem;">
        <div class="quick-access-card">
          <div class="quick-access-icon">🔍</div>
          <div class="quick-access-content">
            <h4>Multiquery</h4>
            <p>Birden fazla PostgreSQL sunucusunda eşzamanlı sorgu çalıştırın</p>
            <a href="/multiquery" class="quick-access-btn">Aç</a>
          </div>
        </div>
        
        <div class="quick-access-card">
          <div class="quick-access-icon">⚙️</div>
          <div class="quick-access-content">
            <h4>PostgreSQL Installation</h4>
            <p>Otomatik PostgreSQL kurulum ve yapılandırma</p>
            <a href="/pg_install" class="quick-access-btn">Aç</a>
          </div>
        </div>
        
        <div class="quick-access-card">
          <div class="quick-access-icon">👨‍💼</div>
          <div class="quick-access-content">
            <h4>Admin Panel</h4>
            <p>Kullanıcı yönetimi ve sistem ayarları</p>
            <a href="/admin" class="quick-access-btn">Aç</a>
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
        const response = await fetch('/api/stats');
        const stats = await response.json();
        
        document.getElementById('adminServers').textContent = stats.servers || 0;
        document.getElementById('adminUsers').textContent = stats.users || 0;
        document.getElementById('adminTodayQueries').textContent = stats.todayQueries || 0;
      } catch (error) {
        console.log('Admin istatistikleri yüklenemedi:', error);
      }
    }

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

                <div class="mb-2">
                  <div class="form-check">
                    <input class="form-check-input" type="checkbox" id="selectAll" onclick="toggleAll(this)">
                    <label class="form-check-label" for="selectAll">Tümünü Seç / Kaldır</label>
                  </div>
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
                      <tr onclick="toggleServerCheckbox({{ s.id }})" style="cursor: pointer;">
                        <td><input class="form-check-input" type="checkbox" name="server_id" value="{{ s.id }}" id="server_{{ s.id }}" onclick="event.stopPropagation();"></td>
                        <td>{{ s.name }}</td>
                        <td class="code">{{ s.host }}</td>
                        <td>{{ s.port }}</td>
                        <td>{{ s.dbname }}</td>
                        <td>{{ s.username }}</td>
                        <td class="text-end">
                          <button class="btn btn-outline-primary btn-sm me-1" type="button" onclick="editServer(event, {{ s.id }}, '{{ s.name }}', '{{ s.host }}', {{ s.port }}, '{{ s.dbname }}', '{{ s.username }}')">Düzenle</button>
                          <button class="btn btn-outline-danger btn-sm" formmethod="post" formaction="{{ url_for('delete_server', sid=s.id) }}" formnovalidate onclick="return confirm('Silinsin mi?');">Sil</button>
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
        <div style="background: #fff3cd; border: 1px solid #ffeaa7; color: #856404; padding: 12px; border-radius: 4px; margin-bottom: 20px;">
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
                  <th>Cores</th>
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
                  <td>{{ result.cpu_cores }}</td>
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
          // Tüm sunucu bilgilerini tek tek envantere ekle
          {% if results %}
            {% for result in results %}
              addSingleToInventory({
                hostname: '{{ result.hostname }}',
                ip: '{{ result.ip }}',
                ssh_port: '{{ result.ssh_port }}',
                ssh_user: '{{ result.ssh_user }}',
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
              });
            {% endfor %}
          {% endif %}
          
          alert('Tüm sunucular envantere eklendi!');
          setTimeout(() => {
            window.location.href = '/sunuculari-listele';
          }, 1000);
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
    servers = db_query("SELECT * FROM servers ORDER BY id DESC")
    return render_template_string(
        TEMPLATE_INDEX,
        title=APP_TITLE,
        servers=servers,
        MAX_ROWS=MAX_ROWS,
        STMT_TIMEOUT_MS=STMT_TIMEOUT_MS,
        theme_script=THEME_SCRIPT,
    )

# Envanter sayfası
@app.route("/envanter")
@require_auth("multiquery")
def envanter():
    return render_template_string(TEMPLATE_ENVANTER, theme_script=THEME_SCRIPT)

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
        
        # SSH bağlantısı yaparak sunucu bilgilerini topla
        try:
            server_info = collect_server_info(hostname, ip, ssh_port, ssh_user, password)
            return render_template_string(TEMPLATE_SUNUCU_BILGILERI, 
                                        server_info=server_info, 
                                        theme_script=THEME_SCRIPT)
        except Exception as e:
            flash(f"Sunucuya bağlanırken hata oluştu: {str(e)}", "danger")
            return render_template_string(TEMPLATE_MANUEL_SUNUCU_EKLE, theme_script=THEME_SCRIPT)
    
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
            flash(f"Sunucu başarıyla {message}!", "success")
        else:
            flash(f"Sunucu kaydedilemedi: {message}", "danger")
            
    except Exception as e:
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
        
        try:
            # Excel dosyasını oku
            import pandas as pd
            df = pd.read_excel(excel_file)
            
            # İlk sütundan sunucu isimlerini al
            server_names = df.iloc[:, 0].dropna().astype(str).tolist()
            
            if not server_names:
                flash("Excel dosyasında sunucu ismi bulunamadı.", "danger")
                return render_template_string(TEMPLATE_TOPLU_SUNUCU_EKLE, theme_script=THEME_SCRIPT)
            
            # Her sunucu için bilgi topla
            results = []
            for hostname in server_names:
                try:
                    # Hostname'i IP'ye çevirmeye çalış
                    try:
                        ip = socket.gethostbyname(hostname)
                    except:
                        ip = hostname  # IP çevrilemezse hostname'i kullan
                    
                    # Sunucu bilgilerini topla
                    server_info = collect_server_info(hostname, ip, ssh_port, ssh_user, ssh_password)
                    results.append(server_info)
                    
                except Exception as e:
                    # Hata durumunda boş bilgi ekle
                    results.append({
                        'hostname': hostname,
                        'ip': 'Bağlanamadı',
                        'ssh_port': ssh_port,
                        'ssh_user': ssh_user,
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
            
            return render_template_string(TEMPLATE_TOPLU_SUNUCU_EKLE, 
                                        results=results, 
                                        theme_script=THEME_SCRIPT)
            
        except Exception as e:
            flash(f"Excel dosyası işlenirken hata oluştu: {str(e)}", "danger")
            return render_template_string(TEMPLATE_TOPLU_SUNUCU_EKLE, theme_script=THEME_SCRIPT)
    
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
            # Disk bilgilerini parse et
            import json
            try:
                disks = json.loads(server['disks']) if server['disks'] else []
                disk_info = ""
                for disk in disks:
                    disk_info += f"{disk['device']} ({disk['mount']}): {disk['size']} toplam, {disk['used']} kullanılan, {disk['available']} boş, %{disk['percent']}\n"
                disk_info = disk_info.strip()
            except:
                disk_info = server['disks'] or "N/A"
            
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
        log_activity(session['user_id'], session['username'], 'export_servers', 
                    f"Sunucu envanteri Excel export - {len(servers)} sunucu", 'sunuculari_listele')
        
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

    placeholders = _in_clause_placeholders(len(selected_ids))
    rows = db_query(f"SELECT * FROM servers WHERE id IN ({placeholders})", tuple(map(int, selected_ids)))
    servers = [dict(r) for r in rows]

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

    placeholders = _in_clause_placeholders(len(ids))
    rows = db_query(f"SELECT * FROM servers WHERE id IN ({placeholders})", tuple(map(int, ids)))
    servers = [dict(r) for r in rows]

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

    placeholders = _in_clause_placeholders(len(ids))
    rows = db_query(f"SELECT * FROM servers WHERE id IN ({placeholders})", tuple(map(int, ids)))
    servers = [dict(r) for r in rows]

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
    permission_pages = ['multiquery', 'pg_install', 'faydali_linkler', 'view_logs']
    
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
                permission_pages = ['multiquery', 'pg_install', 'faydali_linkler', 'view_logs']
                for page in permission_pages:
                    if request.form.get(page):
                        db_execute("""
                            INSERT INTO user_permissions (user_id, page_name, can_access)
                            VALUES (?, ?, 1)
                        """, [user_id, page])
            
            # Yetki değişikliklerini logla
            permission_changes = []
            if session.get('is_admin') and not user['is_admin']:
                permission_pages = ['multiquery', 'pg_install', 'faydali_linkler', 'view_logs']
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


if __name__ == "__main__":
    init_db()
    init_sunucu_envanteri_table()
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=True)
