#!/usr/bin/env python3
import os
import sys

# Anasayfa.py'dan şifreleme fonksiyonlarını import et
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    # Şifreleme fonksiyonlarını test et
    from anasayfa import encrypt_password, decrypt_password, CRYPTO_AVAILABLE
    
    print("=== SIFRELEME SISTEMI TESTI ===")
    print(f"Cryptography mevcut: {CRYPTO_AVAILABLE}")
    
    if CRYPTO_AVAILABLE:
        # Test şifresi
        test_password = "test123"
        print(f"\nOrijinal şifre: {test_password}")
        
        # Şifrele
        encrypted = encrypt_password(test_password)
        print(f"Şifrelenmiş: {encrypted}")
        
        # Çöz
        decrypted = decrypt_password(encrypted)
        print(f"Çözülmüş: {decrypted}")
        
        # Test
        if test_password == decrypted:
            print("✅ Şifreleme sistemi çalışıyor!")
        else:
            print("❌ Şifreleme sistemi hatası!")
    else:
        print("❌ Cryptography kütüphanesi bulunamadı!")
        
except Exception as e:
    print(f"❌ Hata: {e}")
    import traceback
    traceback.print_exc()

print("\n=== TEST TAMAMLANDI ===")
