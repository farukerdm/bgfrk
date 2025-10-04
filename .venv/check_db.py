#!/usr/bin/env python3
import sqlite3
import os

# Veritabanı bağlantısı
conn = sqlite3.connect('mq_meta.db')
cursor = conn.cursor()

print("=== VERİTABANI DURUMU ===")

# Tabloları listele
cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
tables = cursor.fetchall()
print(f"Tablolar: {[table[0] for table in tables]}")

# Sunucu sayısını kontrol et
try:
    cursor.execute("SELECT COUNT(*) FROM sunucu_envanteri")
    count = cursor.fetchone()[0]
    print(f"Toplam sunucu sayısı: {count}")
    
    if count > 0:
        # İlk 5 sunucuyu göster
        cursor.execute("SELECT hostname, ip, ssh_user, ssh_password FROM sunucu_envanteri LIMIT 5")
        print("\nİlk 5 sunucu:")
        for row in cursor.fetchall():
            hostname, ip, ssh_user, ssh_password = row
            has_password = "VAR" if ssh_password else "YOK"
            print(f"  {hostname} ({ip}) - {ssh_user} - Şifre: {has_password}")
            
        # Şifreli kayıt sayısı
        cursor.execute("SELECT COUNT(*) FROM sunucu_envanteri WHERE ssh_password IS NOT NULL AND ssh_password != ''")
        encrypted_count = cursor.fetchone()[0]
        print(f"\nŞifreli kayıt sayısı: {encrypted_count}/{count}")
        
except Exception as e:
    print(f"Hata: {e}")

conn.close()
