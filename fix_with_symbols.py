/bin/env python3
# -*- coding: utf-8 -*-
import re

def fix_with_symbols(filepath):
    """Emoji'leri ASCII-safe sembollerle değiştir"""
    
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
    
    # Emoji'leri güzel ASCII sembollerle değiştir
    symbol_fixes = {
        # Template'deki başlık emoji'leri için
        '[PC]': '[*]',      # Bilgisayar
        '[PG]': '[DB]',     # PostgreSQL/Database
        '[OK]': '[+]',      # Başarılı/Aktif
        '[S]': '[?]',       # Arama/Scan
        '[i]': '[#]',       # Info/İstatistik
        '[X]': '[-]',       # Hata/Pasif
        
        # Metinlerdeki işaretler
        'Basarili': '[+] Basarili',
        'Hata': '[-] Hata',
        
        # Ok işaretleri (zaten var)
        # '<-' ve '->' güzel görünüyor
    }
    
    for old, new in symbol_fixes.items():
        content = content.replace(old, new)
    
    # Başlık için özel düzeltme
    # "gŸ~Š Envanter" gibi bozuk başlıkları düzelt
    content = re.sub(r'[^\x20-\x7E\n\r\t]+\s*Envanter', '### Envanter', content)
    content = re.sub(r'Son Tarama [^\x20-\x7E\n\r\t]+', 'Son Tarama Loglari', content)
    
    with open(filepath, 'w', encoding='ascii', errors='ignore') as f:
        f.write(content)
    
    print("[OK] Emoji'ler ASCII-safe sembollerle degistirildi:")
    print("  [*] = Bilgisayar/Sunucu")
    print("  [DB] = PostgreSQL")
    print("  [+] = Basarili/Aktif")
    print("  [?] = Arama/Tarama")
    print("  [#] = Istatistik")
    print("  [-] = Hata/Pasif")

if __name__ == '__main__':
    fix_with_symbols('.venv/inventory_routes.py')
    print("\nDosya ASCII-safe olarak kaydedildi!")