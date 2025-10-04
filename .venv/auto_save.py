#!/usr/bin/env python3
"""
Otomatik Git Commit ve Push Scripti
Bu script proje dosyalarında değişiklik olduğunda otomatik olarak commit ve push yapar.
"""

import os
import time
import subprocess
import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class GitAutoCommitHandler(FileSystemEventHandler):
    def __init__(self):
        self.last_commit_time = 0
        self.commit_delay = 30  # 30 saniye bekle (çok sık commit yapmamak için)
        
    def on_modified(self, event):
        if event.is_directory:
            return
            
        # Sadece Python, HTML, CSS, JS dosyalarını takip et (ana klasörde)
        if (event.src_path.endswith(('.py', '.html', '.css', '.js', '.txt', '.md')) and 
            not '.venv' in event.src_path and 
            not '.git' in event.src_path):
            self.auto_commit()
    
    def on_created(self, event):
        if event.is_directory:
            return
            
        if (event.src_path.endswith(('.py', '.html', '.css', '.js', '.txt', '.md')) and 
            not '.venv' in event.src_path and 
            not '.git' in event.src_path):
            self.auto_commit()
    
    def auto_commit(self):
        current_time = time.time()
        
        # Çok sık commit yapmamak için bekle
        if current_time - self.last_commit_time < self.commit_delay:
            return
            
        self.last_commit_time = current_time
        
        try:
            # Git status kontrol et
            result = subprocess.run(['git', 'status', '--porcelain'], 
                                  capture_output=True, text=True)
            
            if result.stdout.strip():
                # Değişiklik var, commit yap
                timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                commit_message = f"Auto-save: {timestamp}"
                
                # Add, commit ve push
                subprocess.run(['git', 'add', '.'], check=True)
                subprocess.run(['git', 'commit', '-m', commit_message], check=True)
                subprocess.run(['git', 'push'], check=True)
                
                print(f"✅ Otomatik kayıt yapıldı: {timestamp}")
            else:
                print("ℹ️  Değişiklik yok, commit yapılmadı")
                
        except subprocess.CalledProcessError as e:
            print(f"❌ Git hatası: {e}")
        except Exception as e:
            print(f"❌ Beklenmeyen hata: {e}")

def main():
    print("🚀 Otomatik Git kayıt sistemi başlatılıyor...")
    print("📁 Takip edilen dosya türleri: .py, .html, .css, .js, .txt, .md")
    print("⏰ Commit gecikmesi: 30 saniye")
    print("🛑 Durdurmak için Ctrl+C")
    print("-" * 50)
    
    event_handler = GitAutoCommitHandler()
    observer = Observer()
    observer.schedule(event_handler, '.', recursive=True)
    observer.start()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n🛑 Otomatik kayıt sistemi durduruluyor...")
        observer.stop()
    
    observer.join()
    print("✅ Sistem durduruldu.")

if __name__ == "__main__":
    main()
