# BGFRK Projesi

Bu proje Flask tabanlı bir web uygulamasıdır.

## Kurulum

1. Repository'yi klonlayın:
```bash
git clone https://github.com/farukerdm/bgfrk.git
cd bgfrk
```

2. Sanal ortam oluşturun:
```bash
python -m venv .venv
.venv\Scripts\activate  # Windows
# veya
source .venv/bin/activate  # Linux/Mac
```

3. Gerekli paketleri yükleyin:
```bash
pip install -r requirements.txt
```

## Otomatik Kayıt Sistemi

Projede değişiklik yaptığınızda otomatik olarak GitHub'a kaydetmek için:

```bash
python auto_save.py
```

Bu script:
- Dosya değişikliklerini izler
- 30 saniye gecikme ile otomatik commit yapar
- Değişiklikleri GitHub'a push eder

## Kullanım

Ana uygulamayı çalıştırmak için:
```bash
python anasayfa.py
```

## Özellikler

- Flask web framework
- Pandas ile veri işleme
- Excel dosya desteği
- SSH bağlantı desteği
- PostgreSQL veritabanı desteği
