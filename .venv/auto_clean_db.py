#!/usr/bin/env python3
import sqlite3
import os

print("=== SUNUCU ENVANTERI TEMIZLIK SCRIPTI ===")

# Veritabani baglantisi
conn = sqlite3.connect('mq_meta.db')
cursor = conn.cursor()

try:
    # Mevcut kayitlari kontrol et
    cursor.execute("SELECT COUNT(*) FROM sunucu_envanteri")
    count = cursor.fetchone()[0]
    print(f"Mevcut sunucu sayisi: {count}")
    
    if count > 0:
        # Kayitlari listele
        cursor.execute("SELECT hostname, ip, ssh_user FROM sunucu_envanteri")
        print("\nSilinecek sunucular:")
        for row in cursor.fetchall():
            hostname, ip, ssh_user = row
            print(f"  - {hostname} ({ip}) - {ssh_user}")
        
        # Otomatik temizlik
        print(f"\n{count} adet sunucu kaydi siliniyor...")
        
        # Tum sunucu kayitlarini sil
        cursor.execute("DELETE FROM sunucu_envanteri")
        
        # Auto-increment'i sifirla
        cursor.execute("DELETE FROM sqlite_sequence WHERE name='sunucu_envanteri'")
        
        conn.commit()
        print(f"Basarili! {count} sunucu kaydi silindi!")
        print("Sifreli sistem icin hazir!")
        
    else:
        print("Zaten temiz - hic sunucu kaydi yok.")
        
except Exception as e:
    print(f"Hata: {e}")
    conn.rollback()
finally:
    conn.close()

print("\n=== TEMIZLIK TAMAMLANDI ===")
