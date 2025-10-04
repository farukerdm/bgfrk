#!/usr/bin/env python3
import sqlite3
import os

print("=== SUNUCU ENVANTERİ TEMİZLİK SCRIPTİ ===")

# Veritabanı bağlantısı
conn = sqlite3.connect('mq_meta.db')
cursor = conn.cursor()

try:
    # Mevcut kayıtları kontrol et
    cursor.execute("SELECT COUNT(*) FROM sunucu_envanteri")
    count = cursor.fetchone()[0]
    print(f"Mevcut sunucu sayısı: {count}")
    
    if count > 0:
        # Kayıtları listele
        cursor.execute("SELECT hostname, ip, ssh_user FROM sunucu_envanteri")
        print("\nSilinecek sunucular:")
        for row in cursor.fetchall():
            hostname, ip, ssh_user = row
            print(f"  - {hostname} ({ip}) - {ssh_user}")
        
        # Kullanıcıdan onay al
        print(f"\n{count} adet sunucu kaydı silinecek.")
        response = input("Devam etmek istiyor musunuz? (e/h): ").lower()
        
        if response == 'e' or response == 'evet':
            # Tüm sunucu kayıtlarını sil
            cursor.execute("DELETE FROM sunucu_envanteri")
            
            # Auto-increment'i sıfırla
            cursor.execute("DELETE FROM sqlite_sequence WHERE name='sunucu_envanteri'")
            
            conn.commit()
            print(f"\n✅ {count} sunucu kaydı başarıyla silindi!")
            print("✅ Şifreli sistem için hazır!")
            
        else:
            print("❌ İşlem iptal edildi.")
    else:
        print("✅ Zaten temiz - hiç sunucu kaydı yok.")
        
except Exception as e:
    print(f"❌ Hata: {e}")
    conn.rollback()
finally:
    conn.close()

print("\n=== TEMİZLİK TAMAMLANDI ===")
