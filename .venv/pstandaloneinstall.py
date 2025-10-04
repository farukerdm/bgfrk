import os
import sys
import platform
import subprocess
import tempfile
from pathlib import Path
from typing import Optional, Tuple, List, Callable
import io
import shlex
from datetime import datetime
import threading
import queue
import urllib.parse
import uuid
import time

try:
    import paramiko
except Exception:
    paramiko = None

from flask import Flask, request, render_template_string, jsonify, Response, stream_with_context
import requests

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "change-me-in-production")

# ====== Geçici payload deposu (token -> data) ======
_PAYLOAD_STORE: dict[str, dict] = {}
_PAYLOAD_TTL_SEC = 600  # 10 dk


def _store_payload(data: dict) -> str:
    token = uuid.uuid4().hex
    _PAYLOAD_STORE[token] = {"ts": time.time(), "data": data}
    return token


def _get_payload(token: str) -> Optional[dict]:
    rec = _PAYLOAD_STORE.get(token)
    if not rec:
        return None
    if time.time() - rec["ts"] > _PAYLOAD_TTL_SEC:
        _PAYLOAD_STORE.pop(token, None)
        return None
    return rec["data"]


def _cleanup_payloads():
    now = time.time()
    dead = [k for k, v in _PAYLOAD_STORE.items() if now - v["ts"] > _PAYLOAD_TTL_SEC]
    for k in dead:
        _PAYLOAD_STORE.pop(k, None)


# ====================== HTML ======================

FORM_HTML = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>PostgreSQL Otomatik Kurulum</title>
  <style>
    /* CSS Variables for theming */
    :root {
      --bg: #f8fafc;
      --panel: #ffffff;
      --muted: #64748b;
      --txt: #1e293b;
      --brand: #3b82f6;
      --accent: #06b6d4;
      --ring: rgba(59,130,246,.35);
      --drop: #ffffff;
      --hover: #f1f5f9;
      --border: #e5e7eb;
    }
    
    /* Dark mode variables */
    [data-theme="dark"] {
      --bg: #0f1216;
      --panel: #171b21;
      --muted: #9aa5b1;
      --txt: #eef2f6;
      --brand: #50b0ff;
      --accent: #7cf;
      --ring: rgba(80,176,255,.35);
      --drop: #0f1216;
      --hover: #212833;
      --border: #242b37;
    }
    
    * { margin: 0; padding: 0; box-sizing: border-box; }
    
    body { 
      font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif; 
      margin: 24px; 
      color: var(--txt); 
      background: var(--bg);
      min-height: 100vh;
    }
    
    [data-theme="dark"] body { 
      background: linear-gradient(135deg, #0c0f13, #0f1216); 
    }
    
    [data-theme="light"] body { 
      background: linear-gradient(135deg, #f1f5f9, #f8fafc); 
    }
    
    .card { 
      max-width: 780px; 
      margin: 0 auto; 
      border: 1px solid var(--border); 
      border-radius: 12px; 
      padding: 24px; 
      box-shadow: 0 4px 24px rgba(0,0,0,0.06);
      background: var(--panel);
    }    
    
    h1 { 
      margin-top: 0; 
      font-size: 1.8rem;
      font-weight: 700;
      background: linear-gradient(135deg, var(--brand), var(--accent));
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
    }
    
    label { 
      display:block; 
      margin: 12px 0 6px; 
      font-weight: 600; 
      color: var(--txt);
    }
    
    input, select, textarea { 
      width: 100%; 
      padding: 10px 12px; 
      border: 1px solid var(--border); 
      border-radius: 8px; 
      background: var(--panel);
      color: var(--txt);
    }
    
    input:focus, select:focus, textarea:focus { 
      outline: none; 
      border-color: var(--brand); 
      box-shadow: 0 0 0 3px var(--ring); 
    }
    
    .row { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
    .help { color: var(--muted); font-size: 12px; margin-top: 4px;}
    
    button { 
      margin-top: 16px; 
      padding: 12px 16px; 
      background: var(--brand); 
      color: white; 
      border: 0; 
      border-radius: 8px; 
      cursor:pointer; 
      font-weight:600;
      transition: all 0.2s;
    }
    
    button:hover { 
      background: var(--accent); 
      transform: translateY(-1px);
    }
    
    .warn { 
      background: rgba(245, 158, 11, 0.1); 
      border: 1px solid #fed7aa; 
      color: #f59e0b; 
      padding: 10px 12px; 
      border-radius: 8px; 
      margin-top: 12px; 
    }
    
    .ok { 
      background: rgba(6, 182, 212, 0.1); 
      border: 1px solid #a5f3fc; 
      color: #06b6d4; 
      padding: 10px 12px; 
      border-radius: 8px; 
      margin-top: 12px; 
      white-space: pre-wrap; 
    }
    
    .err { 
      background: rgba(239, 68, 68, 0.1); 
      border: 1px solid #fecaca; 
      color: #ef4444; 
      padding: 10px 12px; 
      border-radius: 8px; 
      margin-top: 12px; 
      white-space: pre-wrap; 
    }
    
    .section { 
      margin-top: 20px; 
      padding-top: 8px; 
      border-top: 1px dashed var(--border); 
    }
    
    .hidden { display:none; }
    
    code, pre.preview { 
      background: #0b1020; 
      color: #e5e7eb; 
      padding: 8px 10px; 
      border-radius: 8px; 
      font-size: 12px; 
    }
    
    pre#logsBox { 
      background: #0b1020; 
      color: #e5e7eb; 
      padding: 12px; 
      border-radius: 10px; 
      min-height: 200px; 
      max-height: 420px; 
      overflow: auto; 
    }
    
    .status-chip { 
      display: inline-block; 
      font-size: 12px; 
      border-radius: 999px; 
      padding: 4px 10px; 
      margin-left: 8px;
    }
    
    .status-running { 
      background: rgba(245, 158, 11, 0.1); 
      color: #f59e0b; 
      border: 1px solid #fed7aa;
    }
    
    .status-ok { 
      background: rgba(16, 185, 129, 0.1); 
      color: #10b981; 
      border: 1px solid #a5f3fc;
    }
    
    .status-err { 
      background: rgba(239, 68, 68, 0.1); 
      border: 1px solid #fecaca; 
      color: #ef4444;
    }
    
    /* Theme toggle button */
    .theme-toggle {
      position: fixed;
      top: 20px;
      right: 20px;
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 50%;
      width: 50px;
      height: 50px;
      display: flex;
      align-items: center;
      justify-content: center;
      cursor: pointer;
      font-size: 20px;
      z-index: 1000;
      transition: all 0.2s;
      box-shadow: 0 4px 12px rgba(0,0,0,0.15);
    }
    
    .theme-toggle:hover {
      transform: scale(1.1);
      box-shadow: 0 6px 16px rgba(0,0,0,0.2);
    }
  </style>
</head>
<body>
  <button class="theme-toggle" id="themeToggle" title="Dark/Light Mode Toggle">
    <span id="themeIcon">🌙</span>
  </button>
  
  <div class="card">
    <h1>PostgreSQL Otomatik Kurulum <span id="status" class="status-chip">Hazır</span></h1>
    <div style="display:flex; justify-content:flex-end; margin-bottom:8px;">
      <button type="button" onclick="location.href='/'" style="background:#6b7280; color:white; border:0; padding:8px 16px; border-radius:4px; cursor:pointer;">Ana Sayfaya Dön</button>
    </div>
    <p class="warn">Bu işlem yönetici yetkileri gerektirir ve sisteminizde değişiklik yapar. Devam etmeden önce önemli verilerinizi yedekleyin.</p>
    <form id="pgForm" method="POST" action="/pg_prepare_install">
      <label>Hedef İşletim Sistemi</label>
      <select id="osSelect" name="target_os" required>
        <option value="auto" selected>Seçin veya Otomatik Algıla</option>
        <option value="windows">Windows</option>
        <option value="linux">Linux (Debian/Ubuntu)</option>
        <option value="redhat">Linux (RHEL/CentOS/Alma/Rocky)</option>
      </select>

      <script>
        (function(){
          function toggle(id, show){ var el=document.getElementById(id); if(!el) return; show?el.classList.remove('hidden'):el.classList.add('hidden'); }
          function pgShowSection(val){
            val = (val || '').toLowerCase();
            toggle('windows-section', false);
            toggle('linux-deb-section', false);
            toggle('redhat-section', false);
            toggle('db-section', false);
            if(val === 'windows'){ toggle('windows-section', true); toggle('db-section', true); }
            else if(val === 'linux'){ toggle('linux-deb-section', true); toggle('db-section', true); }
            else if(val === 'redhat'){ toggle('redhat-section', true); toggle('db-section', true); }
          }
          window.pgShowSection = pgShowSection;
          var sel = document.getElementById('osSelect'); if(sel){ sel.addEventListener('change', function(){ pgShowSection(this.value); }); pgShowSection(sel.value); }
        })();
      </script>

      <!-- Windows -->
      <div id="windows-section" class="section os-section hidden">
        <h3>Windows için (EDB Silent Installer)</h3>
        <label>Installer URL (.exe)</label>
        <input name="win_installer_url" placeholder="https://get.enterprisedb.com/postgresql/postgresql-16.x-windows-x64.exe" />
        <div class="help">EDB resmi installer URL'sini girin. İndirilip 'silent' parametrelerle kurulacaktır.</div>

        <label>Kurulum Dizini (prefix)</label>
        <input name="win_prefix" value="C:\\\\Program Files\\\\PostgreSQL\\\\16" />

        <label>Veri Dizini (data dir)</label>
        <input name="win_datadir" value="C:\\\\PostgreSQL\\\\data" />

        <label>Servis Adı</label>
        <input name="win_servicename" value="postgresql-x64-16" />
      </div>

      <!-- Debian/Ubuntu -->
      <div id="linux-deb-section" class="section os-section hidden">
        <h3>Linux (Debian/Ubuntu) için</h3>
        <label>Data Dizini (opsiyonel)</label>
        <input name="linux_datadir" placeholder="/var/lib/postgresql/16/main" />
      </div>

      <!-- RHEL/Alma/Rocky -->
      <div id="redhat-section" class="section os-section hidden">
        <h3>Red Hat Tabanlı Sunucuya SSH ile Kurulum</h3>
        <div class="help">Uzak (RHEL/CentOS/Alma/Rocky) sunucuya SSH ile kurulum yapar.</div>
        <label>Uzak Sunucu Hostname/IP</label>
        <input name="ssh_host" placeholder="10.0.0.10" />
        <div class="row">
          <div>
            <label>SSH Kullanıcı</label>
            <input name="ssh_user" value="root" />
          </div>
          <div>
            <label>SSH Port</label>
            <input name="ssh_port" type="number" value="22" />
          </div>
        </div>

        <label>Kimlik Doğrulama Türü</label>
        <select name="ssh_auth_type">
          <option value="password">Parola</option>
          <option value="key">Özel Anahtar (PEM)</option>
        </select>

        <label>SSH Parola (auth=password)</label>
        <input name="ssh_password" type="password" />

        <label>SSH Özel Anahtar İçeriği (auth=key)</label>
        <textarea name="ssh_key" rows="5" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----
...
-----END OPENSSH PRIVATE KEY-----"></textarea>

        <div class="section">
          <h4>Paket Yöneticisi Seçimi</h4>
          <label>Paket Yöneticisi</label>
          <select name="rh_package_manager">
            <option value="auto" selected>Otomatik (dnf/yum)</option>
            <option value="dnf">dnf (Fedora/RHEL 8+)</option>
            <option value="yum">yum (RHEL/CentOS 7)</option>
          </select>
          <div class="help">Bazı sistemlerde dnf bulunmayabilir, bu durumda yum kullanın.</div>
        </div>

        <div class="section">
          <h4>Gelişmiş: Dizinler</h4>
          <label>Data Dizini (PGDATA)</label>
          <input name="rh_data_dir" placeholder="/data/pg/16/data" />
          <div class="help">Boş bırakırsanız varsayılan: /var/lib/pgsql/&lt;ver&gt;/data</div>

          <label>WAL Dizini (opsiyonel)</label>
          <input name="rh_wal_dir" placeholder="/wal/pg/16" />
          <div class="help">Ayrı disk kullanmak için; initdb sırasında -X ile ayarlanır.</div>
        </div>

        <div class="section">
          <h4>Gelişmiş: Erişim (pg_hba.conf)</h4>

          <div>
            <label>Bağlantı Tipi</label>
            <label><input type="radio" name="rh_hba_type" value="local" checked /> local (Unix socket)</label>
            <label><input type="radio" name="rh_hba_type" value="host" /> host (TCP / localhost)</label>
          </div>

          <div id="hba-host-addr" class="hidden">
            <label>Adres (localhost)</label>
            <select id="rh_hba_addr_sel" name="rh_hba_addr_sel">
              <option value="127.0.0.1/32" selected>127.0.0.1/32 (IPv4)</option>
              <option value="::1/128">::1/128 (IPv6)</option>
              <option value="custom">Özel CIDR...</option>
            </select>
            <input id="rh_hba_addr_custom" name="rh_hba_addr_custom" class="hidden" placeholder="örn: 10.0.0.0/24" />
          </div>

          <div class="row">
            <div>
              <label>Database</label>
              <input id="rh_hba_db" name="rh_hba_db" value="all" />
              <div class="help">Virgülle çoklu yazılabilir. Varsayılan: all</div>
            </div>
            <div>
              <label>User</label>
              <input id="rh_hba_user" name="rh_hba_user" value="all" />
              <div class="help">Virgülle çoklu yazılabilir. Varsayılan: all</div>
            </div>
          </div>

          <label>Method</label>
          <select id="rh_hba_method" name="rh_hba_method">
            <option value="scram-sha-256" selected>scram-sha-256</option>
            <option value="md5">md5</option>
            <option value="trust">trust</option>
            <option value="peer">peer (yalnızca local)</option>
          </select>

          <label style="margin-top:12px;">HBA Güncelleme Modu</label>
          <select id="rh_hba_mode" name="rh_hba_mode">
            <option value="append">Sona ekle (mevcut kalır)</option>
            <option value="upsert" selected>Upsert (varsa değiştir, yoksa ekle)</option>
            <option value="replace_all">Benzerleri # ile yoruma al, sonra ekle</option>
            <option value="managed_block">Yönetilen blok olarak yaz</option>
          </select>

          <div style="margin-top:10px;">
            <div class="help">Eklenecek/Güncellenecek satır (önizleme):</div>
            <pre class="preview" id="hbaPreview">local all all scram-sha-256</pre>
          </div>

          <label style="margin-top:12px;">Toplu Kurallar (bir satır = bir kural)</label>
          <textarea id="rh_hba_bulk" name="rh_hba_bulk" rows="8" placeholder="# İstersen yorumlar ve boş satırlar bırakabilirsin
# local <db> <user> <method>
# host  <db> <user> <addr/CIDR> <method>
local  all     all                                     peer
# IPv4 local connections:
host   all     all               127.0.0.1/32          trust
# IPv6 local connections:
host   all     all               ::1/128               trust
host   all     all               0.0.0.0/0             scram-sha-256"></textarea>

          <label style="margin-top:8px;">
            <input type="checkbox" name="rh_hba_bulk_raw" checked />
            Toplu kuralları <b>aynen (RAW)</b> yaz (yorumlar/boşluklar korunur). <span class="help">RAW yalnızca append/managed_block ile kullanılır.</span>
          </label>

          <label style="margin-top:12px;">
            <input type="checkbox" name="rh_hba_apply" checked />
            Bu kural(lar)ı <b>onaylıyorum</b> ve kuruluma başla
          </label>
        </div>

        <div class="section">
          <h4>PostgreSQL Extension'ları</h4>
          <div class="help">Kurulum sırasında yüklenecek extension'ları seçin.</div>

          <!-- Contrib Paketi ile Gelen Extension'lar -->
          <div style="margin: 16px 0;">
            <h5 style="color: #059669; margin-bottom: 8px;">📦 Contrib Paketi ile Gelen Extension'lar (Zaten Kurulu)</h5>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 12px;">
              <label style="display: flex; align-items: center; padding: 8px; border: 1px solid #10b981; border-radius: 6px; cursor: pointer; background-color: #f0fdf4;">
                <input type="checkbox" name="extension_postgres_fdw" style="margin-right: 8px;" />
                <div>
                  <strong>postgres_fdw</strong>
                  <div style="font-size: 12px; color: #059669;">Foreign Data Wrapper for PostgreSQL</div>
                </div>
              </label>

              <label style="display: flex; align-items: center; padding: 8px; border: 1px solid #10b981; border-radius: 6px; cursor: pointer; background-color: #f0fdf4;">
                <input type="checkbox" name="extension_pg_stat_statements" style="margin-right: 8px;" />
                <div>
                  <strong>pg_stat_statements</strong>
                  <div style="font-size: 12px; color: #059669;">Query performance statistics</div>
                </div>
              </label>

              <label style="display: flex; align-items: center; padding: 8px; border: 1px solid #10b981; border-radius: 6px; cursor: pointer; background-color: #f0fdf4;">
                <input type="checkbox" name="extension_uuid_ossp" style="margin-right: 8px;" />
                <div>
                  <strong>uuid-ossp</strong>
                  <div style="font-size: 12px; color: #059669;">UUID generation functions</div>
                </div>
              </label>

              <label style="display: flex; align-items: center; padding: 8px; border: 1px solid #10b981; border-radius: 6px; cursor: pointer; background-color: #f0fdf4;">
                <input type="checkbox" name="extension_hstore" style="margin-right: 8px;" />
                <div>
                  <strong>hstore</strong>
                  <div style="font-size: 12px; color: #059669;">Key-value pair data type</div>
                </div>
              </label>

              <label style="display: flex; align-items: center; padding: 8px; border: 1px solid #10b981; border-radius: 6px; cursor: pointer; background-color: #f0fdf4;">
                <input type="checkbox" name="extension_ltree" style="margin-right: 8px;" />
                <div>
                  <strong>ltree</strong>
                  <div style="font-size: 12px; color: #059669;">Hierarchical tree data type</div>
                </div>
              </label>
            </div>
          </div>

          <!-- Harici Paket Gerektiren Extension'lar -->
          <div style="margin: 16px 0;">
            <h5 style="color: #dc2626; margin-bottom: 8px;">🔧 Harici Paket Gerektiren Extension'lar</h5>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 12px;">
              <label style="display: flex; align-items: center; padding: 8px; border: 1px solid #ef4444; border-radius: 6px; cursor: pointer; background-color: #fef2f2;">
                <input type="checkbox" name="extension_pgaudit" style="margin-right: 8px;" />
                <div>
                  <strong>pgAudit</strong>
                  <div style="font-size: 12px; color: #dc2626;">Audit logging extension</div>
                </div>
              </label>

              <label style="display: flex; align-items: center; padding: 8px; border: 1px solid #ef4444; border-radius: 6px; cursor: pointer; background-color: #fef2f2;">
                <input type="checkbox" name="extension_oracle_fdw" style="margin-right: 8px;" />
                <div>
                  <strong>oracle_fdw</strong>
                  <div style="font-size: 12px; color: #dc2626;">Foreign Data Wrapper for Oracle</div>
                </div>
              </label>

              <label style="display: flex; align-items: center; padding: 8px; border: 1px solid #ef4444; border-radius: 6px; cursor: pointer; background-color: #fef2f2;">
                <input type="checkbox" name="extension_tds_fdw" style="margin-right: 8px;" />
                <div>
                  <strong>tds_fdw</strong>
                  <div style="font-size: 12px; color: #dc2626;">Foreign Data Wrapper for SQL Server</div>
                </div>
              </label>

              <label style="display: flex; align-items: center; padding: 8px; border: 1px solid #ef4444; border-radius: 6px; cursor: pointer; background-color: #fef2f2;">
                <input type="checkbox" name="extension_mysql_fdw" style="margin-right: 8px;" />
                <div>
                  <strong>mysql_fdw</strong>
                  <div style="font-size: 12px; color: #dc2626;">Foreign Data Wrapper for MySQL</div>
                </div>
              </label>

              <label style="display: flex; align-items: center; padding: 8px; border: 1px solid #ef4444; border-radius: 6px; cursor: pointer; background-color: #fef2f2;">
                <input type="checkbox" name="extension_pg_cron" style="margin-right: 8px;" />
                <div>
                  <strong>pg_cron</strong>
                  <div style="font-size: 12px; color: #dc2626;">Job scheduler extension</div>
                </div>
              </label>
            </div>
          </div>

          <div style="margin-top: 12px;">
            <label>
              <input type="checkbox" name="extension_auto_create" checked />
              Seçilen extension'ları otomatik olarak CREATE EXTENSION ile aktifleştir
            </label>
            <div class="help">Bu seçenek işaretliyse, extension'lar kurulum sonrası otomatik olarak veritabanında aktifleştirilir.</div>
          </div>
        </div>
      </div>

      <!-- DB common -->
      <div id="db-section" class="section hidden">
        <h3>Veritabanı Ayarları</h3>
        <div class="row">
          <div>
            <label>PostgreSQL Versiyon (örn: 16)</label>
            <input name="pg_version" placeholder="16" />
          </div>
          <div>
            <label>Port</label>
            <input name="port" type="number" value="5432" required />
          </div>
        </div>

        <div class="row">
          <div>
            <label>Postgres Süper Kullanıcı Şifresi</label>
            <input name="superuser_password" type="password" required />
          </div>
          <div>
            <label>Locale (opsiyonel)</label>
            <input name="locale" placeholder="en_US.UTF-8 veya tr_TR.UTF-8" />
          </div>
        </div>

        <div style="margin-top:12px;">
          <label style="font-weight: 600; margin-bottom: 8px; display: block;">Kurulacak Bileşenleri Seçin:</label>

          <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 8px; margin-bottom: 12px;">
            <label style="font-weight: normal; margin: 4px 0;">
              <input type="checkbox" name="component_server" checked />
              Server (Ana PostgreSQL sunucusu)
            </label>

            <label style="font-weight: normal; margin: 4px 0;">
              <input type="checkbox" name="component_client" checked />
              Client (psql, pg_dump vb.)
            </label>

            <label style="font-weight: normal; margin: 4px 0;">
              <input type="checkbox" name="component_libs" />
              Libs (libpq, geliştirici kütüphaneleri)
            </label>

            <label style="font-weight: normal; margin: 4px 0;">
              <input type="checkbox" name="component_contrib" />
              Contrib (Ek modüller)
            </label>

            <label style="font-weight: normal; margin: 4px 0;">
              <input type="checkbox" name="component_devel" />
              Devel (Geliştirme başlıkları)
            </label>

            <label style="font-weight: normal; margin: 4px 0;">
              <input type="checkbox" name="component_plperl" />
              PL/Perl (Perl prosedür dili)
            </label>

            <label style="font-weight: normal; margin: 4px 0;">
              <input type="checkbox" name="component_plpython3" />
              PL/Python3 (Python3 prosedür dili)
            </label>

            <label style="font-weight: normal; margin: 4px 0;">
              <input type="checkbox" name="component_pltcl" />
              PL/Tcl (Tcl prosedür dili)
            </label>

            <label style="font-weight: normal; margin: 4px 0;">
              <input type="checkbox" name="component_docs" />
              Docs (Dokümantasyon)
            </label>

            <label style="font-weight: normal; margin: 4px 0;">
              <input type="checkbox" name="component_jit" />
              JIT (Just-In-Time derleyici)
            </label>
          </div>

          <div style="margin-top: 8px;">
            <button type="button" onclick="toggleAllComponents(true)" style="margin-right: 8px; padding: 6px 12px; background: #6b7280; color: white; border: 0; border-radius: 4px; cursor: pointer; font-size: 12px;">Tümünü Seç</button>
            <button type="button" onclick="toggleAllComponents(false)" style="padding: 6px 12px; background: #6b7280; color: white; border: 0; border-radius: 4px; cursor: pointer; font-size: 12px;">Hiçbirini Seçme</button>
          </div>
        </div>

        <!-- PostgreSQL Konfigürasyon -->
        <div class="section">
          <h3>PostgreSQL Konfigürasyon</h3>
          <div class="help">postgresql.conf dosyası için otomatik ve özel konfigürasyon parametreleri.</div>

          <div style="margin: 12px 0;">
            <label>
              <input type="checkbox" id="enableConfig" name="enable_config" />
              PostgreSQL konfigürasyonu etkinleştir
            </label>
          </div>

          <div id="configPanel" class="hidden">
            <div style="margin: 16px 0; padding: 16px; background: #f0f9ff; border: 1px solid #0ea5e9; border-radius: 8px;">
              <h4 style="margin-top: 0; color: #0c4a6e;">Konfigürasyon Parametreleri</h4>

              <div style="margin-top: 12px;">
                <button type="button" id="loadAutoConfigBtn" style="margin-bottom: 12px; padding: 8px 16px; background: #059669; color: white; border: 0; border-radius: 6px; cursor: pointer; font-weight: 600;">
                  Otomatik Konfigürasyon Parametrelerini Yükle
                </button>
              </div>

              <div style="margin-top: 12px;">
                <label>postgresql.conf Parametreleri</label>
                <textarea id="postgresqlConfig" name="postgresql_config" rows="12" placeholder="# postgresql.conf ayarları&#10;# Her satır bir parametre olmalıdır&#10;# Örnek:&#10;shared_buffers = 256MB&#10;work_mem = 4MB&#10;maintenance_work_mem = 64MB&#10;max_connections = 100&#10;checkpoint_completion_target = 0.9"></textarea>
                <div class="help">Her satır bir parametre olmalıdır. Format: parametre_adı = değer</div>
              </div>

              <div style="margin-top: 16px;">
                <button type="button" id="applyConfigBtn" style="padding: 10px 20px; background: #dc2626; color: white; border: 0; border-radius: 6px; cursor: pointer; font-weight: 600;">
                  Konfigürasyonu Uygula (postgresql.conf)
                </button>
                <div style="margin-top: 8px; font-size: 12px; color: #dc2626;">
                  ⚠️ Bu işlem mevcut postgresql.conf dosyasını güncelleyecektir!
                </div>
              </div>
            </div>
          </div>
        </div>

        <button id="startBtn" type="submit">Kurulumu Başlat</button>
      </div>
    </form>

    <div id="liveLogs" class="section hidden">
      <h3>Kurulum Günlüğü</h3>
      <pre id="logsBox"></pre>
    </div>

    <script>
      (function(){
        function $(id){ return document.getElementById(id); }
        var form = $('pgForm');
        var btn = $('startBtn');
        var panel = $('liveLogs');
        var box = $('logsBox');
        var statusChip = $('status');
        var es;

        function setStatus(cls, text){
          statusChip.className = 'status-chip ' + cls;
          statusChip.textContent = text;
        }

        function hbaUpdate(){
          var type = (document.querySelector('input[name="rh_hba_type"]:checked')||{}).value || 'local';
          var db = ( $('rh_hba_db') ? $('rh_hba_db').value.trim() : 'all') || 'all';
          var user = ( $('rh_hba_user') ? $('rh_hba_user').value.trim() : 'all') || 'all';
          var methodSel = $('rh_hba_method');
          var method = methodSel ? methodSel.value : 'scram-sha-256';
          var hostArea = $('hba-host-addr');
          if(type === 'host'){ hostArea && hostArea.classList.remove('hidden'); }
          else { hostArea && hostArea.classList.add('hidden'); }
          if(method === 'peer' && type !== 'local'){
            method = 'md5'; if(methodSel){ methodSel.value = 'md5'; }
          }
          var addr = '';
          if(type === 'host'){
            var sel = $('rh_hba_addr_sel');
            var v = sel ? sel.value : '127.0.0.1/32';
            if(v === 'custom'){
              var cust = $('rh_hba_addr_custom');
              cust && cust.classList.remove('hidden');
              addr = (cust ? cust.value.trim() : '') || '127.0.0.1/32';
            }else{
              $('rh_hba_addr_custom') && $('rh_hba_addr_custom').classList.add('hidden');
              addr = v;
            }
          }
          var line = (type === 'local')
            ? ('local ' + (db||'all') + ' ' + (user||'all') + ' ' + method)
            : ('host '  + (db||'all') + ' ' + (user||'all') + ' ' + (addr||'127.0.0.1/32') + ' ' + method);
          var prev = $('hbaPreview'); if(prev){ prev.textContent = line; }
        }
        ['rh_hba_db','rh_hba_user','rh_hba_method','rh_hba_addr_sel','rh_hba_addr_custom'].forEach(function(id){
          var el = $(id); if(el){ el.addEventListener('input', hbaUpdate); el.addEventListener('change', hbaUpdate); }
        });
        var radios = document.querySelectorAll('input[name="rh_hba_type"]');
        radios.forEach(function(r){ r.addEventListener('change', hbaUpdate); });
        hbaUpdate();

        // Component selection toggle functions
        window.toggleAllComponents = function(selectAll) {
          var componentCheckboxes = document.querySelectorAll('input[name^="component_"]');
          componentCheckboxes.forEach(function(checkbox) {
            checkbox.checked = selectAll;
          });
        };

        // Configuration panel toggle
        var enableConfigCheckbox = document.getElementById('enableConfig');
        var configPanel = document.getElementById('configPanel');
        if (enableConfigCheckbox && configPanel) {
          enableConfigCheckbox.addEventListener('change', function() {
            if (this.checked) {
              configPanel.classList.remove('hidden');
            } else {
              configPanel.classList.add('hidden');
            }
          });
        }

        // Load auto configuration button
        var loadAutoConfigBtn = document.getElementById('loadAutoConfigBtn');
        var postgresqlConfigTextarea = document.getElementById('postgresqlConfig');
        if (loadAutoConfigBtn && postgresqlConfigTextarea) {
          loadAutoConfigBtn.addEventListener('click', function() {
            // Otomatik konfigürasyon parametrelerini yükle
            var autoConfig = `# PostgreSQL Otomatik Konfigürasyon Parametreleri
# Bu parametreler performans için optimize edilmiştir

# Bellek Ayarları
shared_buffers = 256MB
effective_cache_size = 1GB
work_mem = 4MB
maintenance_work_mem = 64MB

# Bağlantı Ayarları
max_connections = 100
superuser_reserved_connections = 3

# WAL Ayarları
wal_level = 'replica'
wal_buffers = 16MB
min_wal_size = 80MB
max_wal_size = 1GB
checkpoint_completion_target = 0.9
checkpoint_timeout = '5min'

# Paralel İşlem Ayarları
max_worker_processes = 4
max_parallel_workers = 4
max_parallel_workers_per_gather = 2
max_parallel_maintenance_workers = 2

# Performans Ayarları
random_page_cost = 1.1
effective_io_concurrency = 200
seq_page_cost = 1.0

# Autovacuum Ayarları
autovacuum = on
autovacuum_max_workers = 3
autovacuum_naptime = '1min'

# Logging Ayarları
log_destination = 'stderr'
logging_collector = on
log_directory = 'pg_log'
log_min_duration_statement = '1000ms'

# Diğer Ayarlar
timezone = 'UTC'
shared_preload_libraries = 'pg_stat_statements'
jit = on

# SSL Ayarları
ssl = off`;

            postgresqlConfigTextarea.value = autoConfig;
            alert('Otomatik konfigürasyon parametreleri yüklendi!');
          });
        }

        // Apply configuration button
        var applyConfigBtn = document.getElementById('applyConfigBtn');
        if (applyConfigBtn) {
          applyConfigBtn.addEventListener('click', function() {
            var config = postgresqlConfigTextarea.value.trim();
            if (!config) {
              alert('Konfigürasyon parametreleri boş olamaz!');
              return;
            }

            if (confirm('Bu konfigürasyon postgresql.conf dosyasına uygulanacak. Devam etmek istiyor musunuz?')) {
              // Konfigürasyonu form verisine ekle
              var hiddenInput = document.createElement('input');
              hiddenInput.type = 'hidden';
              hiddenInput.name = 'postgresql_config';
              hiddenInput.value = config;

              // Mevcut hidden input varsa kaldır
              var existingInput = document.querySelector('input[name="postgresql_config"]');
              if (existingInput) {
                existingInput.remove();
              }

              // Form'a ekle
              document.getElementById('installForm').appendChild(hiddenInput);

              alert('Konfigürasyon hazırlandı! Kurulum başlatıldığında postgresql.conf dosyasına uygulanacak.');
            }
          });
        }


        async function toToken(formEl){
          const fd = new FormData(formEl);
          const res = await fetch(formEl.getAttribute('action') || '/pg_prepare_install', { method:'POST', body: fd });
          if(!res.ok) throw new Error('Hazırlık isteği başarısız');
          const data = await res.json();
          return data.token;
        }

        if(form){
          form.addEventListener('submit', async function(ev){
            ev.preventDefault();
            if(panel){ panel.classList.remove('hidden'); }
            if(box){ box.textContent = 'Kurulum başlatılıyor...\\n'; box.scrollTop = box.scrollHeight; }
            if(btn){ btn.disabled = true; }
            setStatus('status-running','Çalışıyor');

            try{
              const token = await toToken(form);
            try{ if(es){ es.close(); } }catch(e){}
              es = new EventSource('/pg_install_stream?token=' + encodeURIComponent(token));
            es.onmessage = function(ev){
              if(!ev || !ev.data) return;
              if(ev.data.startsWith('STATUS:')){
                var st = ev.data.split(':')[1].trim();
                if(st==='success'){ setStatus('status-ok','Başarılı'); }
                else { setStatus('status-err','Başarısız'); }
                if(btn){ btn.disabled = false; }
                try{ es.close(); }catch(e){}
                return;
              }
              if(box){ box.textContent += ev.data + "\\n"; box.scrollTop = box.scrollHeight; }
            };
            es.onerror = function(){
              if(box){ box.textContent += "\\n[HATA] SSE bağlantısı koptu."; box.scrollTop = box.scrollHeight; }
              setStatus('status-err','Bağlantı Hatası');
              if(btn){ btn.disabled = false; }
              try{ es.close(); }catch(e){}
            };
            }catch(err){
              if(box){ box.textContent += "\\n[HATA] " + (err && err.message ? err.message : err); }
              setStatus('status-err','Hazırlık Hatası');
              if(btn){ btn.disabled = false; }
            }
          });
        }
      })();

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
      }

      function toggleTheme() {
        const currentTheme = document.documentElement.getAttribute('data-theme');
        const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
        
        document.documentElement.setAttribute('data-theme', newTheme);
        localStorage.setItem('theme', newTheme);
        
        const themeIcon = document.getElementById('themeIcon');
        if (themeIcon) {
          themeIcon.textContent = newTheme === 'dark' ? '🌙' : '☀️';
        }
      }

      // Initialize theme on page load
      document.addEventListener('DOMContentLoaded', function() {
        initTheme();
        
        const themeToggle = document.getElementById('themeToggle');
        if (themeToggle) {
          themeToggle.addEventListener('click', toggleTheme);
        }
      });
    </script>
  </div>
</body>
</html>
"""

RESULT_HTML = """
<!doctype html>
<html>
<head><meta charset="utf-8" /><title>Kurulum Sonuç</title></head>
<body>
  <pre>{{ logs }}</pre>
</body>
</html>
"""


# ====================== Yardımcılar ======================

def run_local(cmd: List[str] | str, shell: bool = False, env: Optional[dict] = None) -> Tuple[int, str, str]:
    completed = subprocess.run(cmd, shell=shell, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
    return completed.returncode, completed.stdout.strip(), completed.stderr.strip()


def is_admin() -> bool:
    system = platform.system().lower()
    try:
        if system == "windows":
            import ctypes  # type: ignore
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except Exception:
        return False


def detect_os(target_os_field: str) -> str:
    if target_os_field and target_os_field.lower() in ("windows", "linux", "redhat"):
        return target_os_field.lower()
    system = platform.system().lower()
    if "windows" in system:
        return "windows"
    if "linux" in system:
        return "linux"
    return system


def download_file(url: str, dest: Path, emit: Optional[Callable[[str], None]] = None) -> Path:
    if emit: emit(f"[DL] {url} → {dest}")
    resp = requests.get(url, stream=True, timeout=120)
    resp.raise_for_status()
    total = 0
    with open(dest, "wb") as f:
        for chunk in resp.iter_content(chunk_size=1024 * 1024):
            if chunk:
                f.write(chunk);
                total += len(chunk)
                if emit and total % (5 * 1024 * 1024) < 1024 * 1024:
                    emit(f"[DL] {total // 1024 // 1024} MB indirildi...")
    if emit: emit("[DL] tamam.")
    return dest


def ts() -> str:
    return datetime.now().strftime("%H:%M:%S")


# === Bulk HBA yardımcıları ===
def _parse_hba_bulk(text: str) -> List[dict]:
    rules = []
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 4:
            continue
        t = parts[0].lower()
        if t == "local":
            if len(parts) < 4:
                continue
            rules.append({"type": "local", "db": parts[1], "user": parts[2], "addr": None, "method": parts[3]})
        elif t == "host":
            if len(parts) < 5:
                continue
            rules.append({"type": "host", "db": parts[1], "user": parts[2], "addr": parts[3], "method": parts[4]})
    return rules


def _hba_line_from_rule(rule: dict) -> str:
    if rule["type"] == "local":
        return f"local {rule['db']} {rule['user']} {rule['method']}"
    addr = rule.get("addr") or "127.0.0.1/32"
    return f"host {rule['db']} {rule['user']} {addr} {rule['method']}"


# ====================== Windows ======================

def windows_install_with_edb_silent(installer_url: str, prefix: str, datadir: str, servicename: str, password: str,
                                    port: int, locale: Optional[str], postgresql_config: Optional[str] = None,
                                    emit: Optional[Callable[[str], None]] = None):
    def e(msg):
        if emit: emit(f"[{ts()}] {msg}")

    if not installer_url:
        return False, "Windows için installer URL gerekli."
    temp_dir = Path(tempfile.mkdtemp(prefix="pg_install_"))
    installer_path = temp_dir / "postgresql-installer.exe"
    try:
        e("Installer indiriliyor...")
        download_file(installer_url, installer_path, emit=emit)
    except Exception as ex:
        e(f"[ERR] indirilemedi: {ex}")
        return False, f"Installer indirilemedi: {ex}"
    args = [
        str(installer_path),
        "--mode", "unattended",
        "--unattendedmodeui", "none",
        "--superpassword", password,
        "--serverport", str(port),
        "--prefix", prefix,
        "--datadir", datadir,
        "--servicename", servicename,
        "--disable-components", "stackbuilder",
    ]
    if locale:
        args += ["--locale", locale]
    e("Installer çalıştırılıyor (sessiz)...")
    code, out, err = run_local(args, shell=False)
    if emit:
        if out: emit(out)
        if err: emit(err)
        emit(f"[{ts()}] exit={code}")

    if code != 0:
        return False, (out + ("\n" + err if err else "")).strip()

    # Apply PostgreSQL configuration if provided
    if postgresql_config:
        e("[STEP] PostgreSQL konfigürasyonu uygulanıyor...")
        conf_path = Path(datadir) / "postgresql.conf"
        if conf_path.exists():
            try:
                # Parse configuration lines
                config_lines = []
                for line in postgresql_config.split('\n'):
                    line = line.strip()
                    if line and not line.startswith('#'):
                        config_lines.append(line)

                # Read current config
                with open(conf_path, 'r', encoding='utf-8') as f:
                    lines = f.readlines()

                # Apply settings
                updated_lines = []
                applied_settings = set()

                for line in lines:
                    line_stripped = line.strip()
                    if not line_stripped or line_stripped.startswith('#'):
                        updated_lines.append(line)
                        continue

                    if '=' in line_stripped:
                        key = line_stripped.split('=')[0].strip()
                        # Check if this setting is in our config
                        found = False
                        for config_line in config_lines:
                            if config_line.startswith(key + ' ='):
                                updated_lines.append(config_line + '\n')
                                applied_settings.add(key)
                                found = True
                                break
                        if not found:
                            updated_lines.append(line)
                    else:
                        updated_lines.append(line)

                # Add new settings
                for config_line in config_lines:
                    key = config_line.split('=')[0].strip()
                    if key not in applied_settings:
                        updated_lines.append(config_line + '\n')

                # Write back to file
                with open(conf_path, 'w', encoding='utf-8') as f:
                    f.writelines(updated_lines)

                e(f"[OK] {len(config_lines)} konfigürasyon ayarı uygulandı")

                # Restart service
                e("[STEP] PostgreSQL servisi yeniden başlatılıyor...")
                restart_cmd = f"net stop {servicename} && net start {servicename}"
                code2, out2, err2 = run_local(restart_cmd, shell=True)
                if code2 == 0:
                    e("[OK] Servis yeniden başlatıldı")
                else:
                    e(f"[WARN] Servis yeniden başlatılamadı: {err2}")

            except Exception as ex:
                e(f"[WARN] Konfigürasyon uygulanamadı: {ex}")
        else:
            e(f"[WARN] Konfigürasyon dosyası bulunamadı: {conf_path}")

    return True, (out + ("\n" + err if err else "")).strip()


# ====================== Debian/Ubuntu ======================

def linux_install_with_apt(port: int, password: str, locale: Optional[str], datadir: Optional[str],
                           pg_version: Optional[str],
                           install_all_components: bool = False,
                           components: Optional[dict] = None,
                           postgresql_config: Optional[str] = None,
                           emit: Optional[Callable[[str], None]] = None):
    def e(msg):
        if emit: emit(f"[{ts()}] {msg}")

    env = os.environ.copy()
    env["DEBIAN_FRONTEND"] = "noninteractive"

    cmds = [
        "apt-get update -y",
        "apt-get install -y wget gnupg lsb-release ca-certificates",
        "install -d /usr/share/postgresql-common/pgdg && wget -qO - https://www.postgresql.org/media/keys/ACCC4CF8.asc | tee /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc > /dev/null",
        "sh -c 'echo \"deb http://apt.postgresql.org/pub/repos/apt/ $(lsb_release -cs)-pgdg main\" > /etc/apt/sources.list.d/pgdg.list'",
        "apt-get update -y",
        "apt-get install -y postgresql-common",
    ]
    outputs: list[str] = []
    for c in cmds:
        e(f"[CMD] {c}")
        rc, out, err = run_local(["bash", "-lc", c], env=env)
        if out and emit: emit(out)
        if err and emit: emit(err)
        outputs.append(out)
        if rc != 0:
            e(f"[ERR] exit={rc}")
            return False, "\n".join(outputs)
        else:
            e("[OK] exit=0")

    v = (pg_version or "").strip()
    if v and not v.isdigit():
        e("[ERR] Geçersiz versiyon girildi.")
        return False, "PostgreSQL versiyonunu sayı olarak girin (örn: 16)."

    install_cmds: list[str] = []
    if v:
        pkgs = []

        # Server and client are always installed if specified
        if install_all_components or (components and components.get("component_server", False)):
            pkgs.append(f"postgresql-{v}")
        if install_all_components or (components and components.get("component_client", False)):
            pkgs.append(f"postgresql-client-{v}")

        # Add other components based on selection
        if install_all_components or (components and components.get("component_contrib", False)):
            pkgs.append(f"postgresql-contrib-{v}")
        if install_all_components or (components and components.get("component_plpython3", False)):
            pkgs.append(f"postgresql-plpython3-{v}")
        if install_all_components or (components and components.get("component_plperl", False)):
            pkgs.append(f"postgresql-plperl-{v}")
        if install_all_components or (components and components.get("component_pltcl", False)):
            pkgs.append(f"postgresql-pltcl-{v}")
        if install_all_components or (components and components.get("component_docs", False)):
            pkgs.append(f"postgresql-doc-{v}")
        if install_all_components or (components and components.get("component_devel", False)):
            pkgs.append(f"postgresql-server-dev-{v}")
        if install_all_components or (components and components.get("component_libs", False)):
            pkgs.append("libpq-dev")

        if pkgs:
            install_cmds.append("apt-get install -y " + " ".join(pkgs))
    else:
        base_pkg = "postgresql"
        install_cmds.append(f"apt-get install -y {base_pkg}")
        if install_all_components:
            install_cmds.append("apt-get install -y libpq-dev postgresql-contrib")

    for c in install_cmds:
        e(f"[CMD] {c}")
        rc, out, err = run_local(["bash", "-lc", c], env=env)
        if out and emit: emit(out)
        if err and emit: emit(err)
        if rc != 0:
            e(f"[ERR] exit={rc}")
            return False, out or err or c
        else:
            e("[OK] exit=0")

    cmd_check = (
                    "pid=$(ss -ltnp | awk -v p=':%s$' "
                    "'$4 ~ p && /postgres/ {for (i=1;i<=NF;i++) if ($i ~ /pid=/) {sub(\"pid=\",\"\",$i); split($i,a,\",\"); print a[1]; break}}' | head -1); "
                    "if [ -n \"$pid\" ]; then exe=$(readlink -f /proc/$pid/exe); echo $pid $exe; fi"
                ) % (port,)
    e("[CHECK] Port/Process")
    rc, out, _ = run_local(["bash", "-lc", cmd_check])
    if out.strip():
        parts = out.strip().split()
        pid = parts[0] if parts else "?"
        exe = parts[1] if len(parts) > 1 else "?"
        msg = f"[INFO] Port {port} zaten dinleniyor → PID={pid}, exe={exe}"
        outputs.append(msg);
        e(msg)
        return True, "Belirtilen portta PostgreSQL zaten çalışıyor; kurulum atlandı.\n" + "\n".join(outputs)

    password_escaped = password.replace("'", "''")
    set_pwd_cmd = f"sudo -u postgres psql -Atqc \"ALTER USER postgres WITH PASSWORD '{password_escaped}';\""
    for c in [set_pwd_cmd, "sudo -u postgres psql -Atqc \"SHOW config_file;\""]:
        e(f"[CMD] {c}")
        rc, out, err = run_local(["bash", "-lc", c], env=env)
        if out and emit: emit(out)
        if err and emit: emit(err)
        outputs.append(out)
        if rc != 0:
            e(f"[ERR] exit={rc}")
            return False, "\n".join(outputs)
        else:
            e("[OK] exit=0")

    conf_path = outputs[-1].strip()
    e(f"[STEP] Port {port} ayarlanıyor")
    rc, out, err = run_local(["bash", "-lc", f"sed -i \"s/^#\\?port\\s*=\\s*.*/port = {port}/\" '{conf_path}'"],
                             env=env)
    if out and emit: emit(out)
    if err and emit: emit(err)
    if rc != 0:
        e(f"[ERR] exit={rc}")
        return False, "\n".join(outputs)

    e("[STEP] systemctl restart postgresql")
    rc, out, err = run_local(["bash", "-lc", "systemctl restart postgresql"], env=env)
    if out and emit: emit(out)
    if err and emit: emit(err)
    if rc != 0:
        e(f"[ERR] exit={rc}")
        return False, "\n".join(outputs)

    # Apply PostgreSQL configuration if provided
    if postgresql_config:
        e("[STEP] PostgreSQL konfigürasyonu uygulanıyor...")
        try:
            # Parse configuration lines
            config_lines = []
            for line in postgresql_config.split('\n'):
                line = line.strip()
                if line and not line.startswith('#'):
                    config_lines.append(line)

            # Apply each setting
            for config_line in config_lines:
                key_value = config_line.split('=', 1)
                if len(key_value) == 2:
                    key = key_value[0].strip()
                    value = key_value[1].strip()

                    # Update existing setting
                    sed_cmd = f"sudo sed -i 's/^#\\?{key}\\s*=.*/{key} = {value}/' '{conf_path}'"
                    run_local(["bash", "-lc", sed_cmd], env=env)

                    # Add setting if not exists
                    grep_cmd = f"sudo grep -q '^{key}\\s*=' '{conf_path}' || echo '{key} = {value}' | sudo tee -a '{conf_path}' >/dev/null"
                    run_local(["bash", "-lc", grep_cmd], env=env)

            e(f"[OK] {len(config_lines)} konfigürasyon ayarı uygulandı")

            # Restart PostgreSQL service
            e("[STEP] PostgreSQL servisi yeniden başlatılıyor...")
            rc2, out2, err2 = run_local(["bash", "-lc", "sudo systemctl restart postgresql"], env=env)
            if rc2 == 0:
                e("[OK] Servis yeniden başlatıldı")
            else:
                e(f"[WARN] Servis yeniden başlatılamadı: {err2}")

        except Exception as ex:
            e(f"[WARN] Konfigürasyon uygulanamadı: {ex}")

    e("[DONE]")
    return True, "\n".join(outputs)


# ====================== Extension Installation Helper ======================

def install_postgresql_extensions(
        extensions: dict,
        auto_create: bool = False,
        pg_version: str = "17",
        data_dir: str = "/var/lib/pgsql/17/data",
        emit: Optional[Callable[[str], None]] = None
) -> bool:
    """
    Install PostgreSQL extensions based on user selection
    """

    def e(msg: str):
        if emit: emit(f"[EXT] {msg}")

    if not extensions:
        e("No extensions selected")
        return True

    # Extension package mapping for different systems
    extension_packages = {
        "pgaudit": f"postgresql{pg_version}-pgaudit",
        "postgres_fdw": f"postgresql{pg_version}-contrib",  # Built-in
        "oracle_fdw": f"postgresql{pg_version}-oracle-fdw",
        "tds_fdw": f"postgresql{pg_version}-tds-fdw",
        "mysql_fdw": f"postgresql{pg_version}-mysql-fdw",
        "pg_stat_statements": f"postgresql{pg_version}-contrib",  # Built-in
        "pg_cron": f"postgresql{pg_version}-cron",
        "uuid_ossp": f"postgresql{pg_version}-contrib",  # Built-in
        "hstore": f"postgresql{pg_version}-contrib",  # Built-in
        "ltree": f"postgresql{pg_version}-contrib",  # Built-in
    }

    # Extension names for CREATE EXTENSION
    extension_names = {
        "pgaudit": "pgaudit",
        "postgres_fdw": "postgres_fdw",
        "oracle_fdw": "oracle_fdw",
        "tds_fdw": "tds_fdw",
        "mysql_fdw": "mysql_fdw",
        "pg_stat_statements": "pg_stat_statements",
        "pg_cron": "pg_cron",
        "uuid_ossp": "uuid-ossp",
        "hstore": "hstore",
        "ltree": "ltree",
    }

    selected_extensions = [ext for ext, selected in extensions.items() if selected]
    if not selected_extensions:
        e("No extensions selected")
        return True

    e(f"Installing extensions: {', '.join(selected_extensions)}")

    # Install packages
    packages_to_install = set()
    for ext in selected_extensions:
        if ext in extension_packages:
            packages_to_install.add(extension_packages[ext])

    if packages_to_install:
        e(f"Installing packages: {', '.join(packages_to_install)}")
        # This will be implemented in the specific installation functions

    # Create extensions in database if auto_create is enabled
    if auto_create:
        e("Creating extensions in database...")
        for ext in selected_extensions:
            if ext in extension_names:
                ext_name = extension_names[ext]
                e(f"Creating extension: {ext_name}")
                # This will be implemented in the specific installation functions

    return True


# ====================== RHEL/Alma/Rocky (SSH, canlı log) ======================

def redhat_install_over_ssh(
        ssh_host: str,
        ssh_user: str,
        ssh_port: int,
        auth_type: str,
        ssh_password: Optional[str],
        ssh_key: Optional[str],
        db_port: int,
        db_superuser_password: str,
        locale: Optional[str],
        pg_version: Optional[str],
        custom_data_dir: Optional[str],
        custom_wal_dir: Optional[str],
        hba_apply: bool,
        hba_type: Optional[str],
        hba_addr_sel: Optional[str],
        hba_addr_custom: Optional[str],
        hba_db: Optional[str],
        hba_user: Optional[str],
        hba_method: Optional[str],
        hba_mode: str = "upsert",
        hba_bulk: Optional[str] = None,
        hba_bulk_raw: bool = False,
        install_all_components: bool = False,
        components: Optional[dict] = None,
        postgresql_config: Optional[str] = None,
        package_manager: str = "auto",
        extensions: Optional[dict] = None,
        extension_auto_create: bool = False,
        emit: Optional[Callable[[str], None]] = None,
):
    def out(msg: str):
        line = f"[{ts()}] {msg}"
        if emit: emit(line)

    def raw(msg: str):
        if emit: emit(msg)

    if paramiko is None:
        out("Paramiko modülü yok.")
        return False, "Paramiko modülü yüklü değil. Lütfen 'pip install paramiko' ile kurun."

    outputs: list[str] = []

    def ssh_exec(client: "paramiko.SSHClient", cmd: str) -> Tuple[int, str, str]:
        stdin, stdout, stderr = client.exec_command(cmd)
        out_ = stdout.read().decode("utf-8", errors="ignore")
        err_ = stderr.read().decode("utf-8", errors="ignore")
        code_ = stdout.channel.recv_exit_status()
        return code_, out_, err_

    def sh(client: "paramiko.SSHClient", cmd: str) -> bool:
        out(f"[CMD] {cmd}")
        code, o, e = ssh_exec(client, cmd)
        if o: raw(o)
        if e: raw(e)
        raw("[OK] exit=0" if code == 0 else f"[ERR] exit={code}")
        return code == 0

    def _sanitize_csv(s: Optional[str]) -> str:
        if not s: return "all"
        s = ",".join([p.strip() for p in s.split(",") if p.strip()])
        return s or "all"

    def _norm_method(m: Optional[str], _type: str) -> str:
        m = (m or "scram-sha-256").strip().lower()
        if m in ("scram", "scram-sha256", "scram_sha_256"): m = "scram-sha-256"
        if _type == "host" and m == "peer":
            out("[WARN] 'peer' sadece local; 'md5' seçildi.")
            return "md5"
        if m not in ("scram-sha-256", "md5", "trust", "peer"): return "scram-sha-256"
        return m

    def build_hba_line(_type: str, _db: str, _user: str, _method: str, _addr: Optional[str]) -> str:
        if _type == "local":
            return f"local {_db} {_user} {_method}"
        return f"host {_db} {_user} {(_addr or '127.0.0.1/32')} {_method}"

    def upload_text_tmp(client: "paramiko.SSHClient", text: str, tmp_path: str) -> bool:
        try:
            sftp = client.open_sftp()
            with sftp.file(tmp_path, "w") as f:
                f.write(text.replace("\r\n", "\n"))
            sftp.close()
            return True
        except Exception as e:
            raw(f"[ERR] SFTP upload failed: {e}")
            return False

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        out("[STEP] SSH bağlantısı kuruluyor...")
        connect_kwargs: dict = {"hostname": ssh_host, "username": ssh_user, "port": ssh_port, "timeout": 30}
        if auth_type == "key" and ssh_key:
            key_obj = None
            key_io = io.StringIO(ssh_key)
            for key_cls in (
            paramiko.RSAKey, getattr(paramiko, "Ed25519Key", None), getattr(paramiko, "ECDSAKey", None)):
                if key_cls is None: continue
                try:
                    key_io.seek(0);
                    key_obj = key_cls.from_private_key(key_io);
                    break
                except Exception:
                    continue
            if key_obj is None: return False, "Özel anahtar çözümlenemedi (RSA/Ed25519/ECDSA)."
            connect_kwargs["pkey"] = key_obj
        elif auth_type == "password" and ssh_password:
            connect_kwargs["password"] = ssh_password
        else:
            return False, "SSH kimlik doğrulama bilgileri eksik (parola veya anahtar)."

        client.connect(**connect_kwargs)

        out("[STEP] İşletim sistemi bilgisi okunuyor")
        sh(client, "set -e; source /etc/os-release 2>/dev/null || . /usr/lib/os-release; echo $ID; echo $VERSION_ID")

        # Paket yöneticisini belirle
        if package_manager == "auto":
            code, pm_out, _ = ssh_exec(client, "command -v dnf >/dev/null 2>&1 && echo dnf || echo yum")
            pm = (pm_out.strip() or "yum")
        elif package_manager == "dnf":
            pm = "dnf"
        elif package_manager == "yum":
            pm = "yum"
        else:
            pm = "yum"  # fallback

        raw(f"[INFO] Paket yöneticisi: {pm}")

        # Seçilen paket yöneticisinin mevcut olup olmadığını kontrol et
        code, pm_check, _ = ssh_exec(client, f"command -v {pm} >/dev/null 2>&1 && echo 'found' || echo 'not found'")
        if pm_check.strip() != "found":
            raw(f"[WARN] {pm} bulunamadı, yum kullanılıyor")
            pm = "yum"

        out("[STEP] Ön gereksinimler (curl, ca-certificates)")
        sh(client, f"sudo {pm} -y install curl ca-certificates || true")

        code, el_major_out, _ = ssh_exec(client,
                                         ". /etc/os-release 2>/dev/null || . /usr/lib/os-release; echo ${VERSION_ID%%.*}")
        el_major = (el_major_out.strip() or "8")
        code, arch_out, _ = ssh_exec(client, "rpm --eval '%{_arch}' 2>/dev/null || uname -m")
        basearch = (arch_out.strip() or "x86_64")
        if basearch in ("amd64",): basearch = "x86_64"

        ver = (pg_version or "").strip()
        if not ver or not ver.isdigit():
            client.close()
            return False, "Kurulacak sürüm bulunamadı (pg_version belirtin, örn: 16)."

        # ----- PGDG repo kurulumu: resmi repo RPM'i ile -----
        # Çakışabilecek eski 'local' repo dosyalarını sil
        sh(client, "sudo rm -f /etc/yum.repos.d/pgdg*-local.repo || true")

        out("[STEP] PGDG repo RPM kuruluyor")
        repo_rpm = f"https://download.postgresql.org/pub/repos/yum/reporpms/EL-{el_major}-{basearch}/pgdg-redhat-repo-latest.noarch.rpm"
        if not sh(client, f"sudo {pm} -y install {repo_rpm}"):
            client.close()
            return False, "PGDG repo RPM kurulamadı."

        # Dağıtımın dahili postgresql modulünü kapat
        sh(client, f"sudo {pm} -y module reset postgresql || true")
        sh(client, f"sudo {pm} -y module disable postgresql || true")

        out("[STEP] Metadata cache yenileniyor (PGDG)")
        sh(client, f"sudo {pm} clean all || true")
        sh(client, f"sudo {pm} -y makecache || true")
        sh(client, f"{pm} repolist -v || true")

        # ----- Paketler -----
        raw(f"[INFO] Deneniyor: PostgreSQL {ver} ({pm})")
        base_pkgs = []

        # Server and client are always installed if specified
        if install_all_components or (components and components.get("component_server", False)):
            base_pkgs.append(f"postgresql{ver}")
            base_pkgs.append(f"postgresql{ver}-server")
            base_pkgs.append(f"postgresql{ver}-libs")

        if base_pkgs and not sh(client, f"sudo {pm} -y install " + " ".join(base_pkgs)):
            client.close()
            return False, "PostgreSQL ana paket(ler) bulunamadı/kurulamadı."

        # Add other components based on selection
        extra_pkgs = []
        if install_all_components or (components and components.get("component_contrib", False)):
            extra_pkgs.append(f"postgresql{ver}-contrib")
        if install_all_components or (components and components.get("component_devel", False)):
            extra_pkgs.append(f"postgresql{ver}-devel")
        if install_all_components or (components and components.get("component_plpython3", False)):
            extra_pkgs.append(f"postgresql{ver}-plpython3")
        if install_all_components or (components and components.get("component_plperl", False)):
            extra_pkgs.append(f"postgresql{ver}-plperl")
        if install_all_components or (components and components.get("component_pltcl", False)):
            extra_pkgs.append(f"postgresql{ver}-pltcl")
        if install_all_components or (components and components.get("component_jit", False)):
            extra_pkgs.append(f"postgresql{ver}-llvmjit")
        if install_all_components or (components and components.get("component_docs", False)):
            extra_pkgs.append(f"postgresql{ver}-docs")

        # Extra paketlerden biri yoksa kurulum devam etsin diye tek tek dene
        for p in extra_pkgs:
            sh(client, f"sudo {pm} -y install {p} || true")

        final_ver = ver
        service_name = f"postgresql-{final_ver}"
        bin_prefix = f"/usr/pgsql-{final_ver}/bin"
        default_data = f"/var/lib/pgsql/{final_ver}/data"
        data_dir = (custom_data_dir or default_data).rstrip("/")
        wal_dir = (custom_wal_dir or "").strip().rstrip("/")
        initdb_needs_custom = bool(custom_data_dir or custom_wal_dir)
        raw(f"[INFO] Kurulan sürüm: {final_ver}; servis: {service_name}")
        raw(f"[INFO] Veri dizini: {data_dir}")
        if wal_dir: raw(f"[INFO] WAL dizini: {wal_dir}")

        sh(client, "id postgres >/dev/null 2>&1 || sudo useradd -r -s /bin/false postgres || true")
        sh(client,
           f"sudo mkdir -p {shlex.quote(data_dir)} && sudo chown -R postgres:postgres {shlex.quote(data_dir)} && sudo chmod 700 {shlex.quote(data_dir)} || true")
        if wal_dir:
            sh(client,
               f"sudo mkdir -p {shlex.quote(wal_dir)} && sudo chown -R postgres:postgres {shlex.quote(wal_dir)} && sudo chmod 700 {shlex.quote(wal_dir)} || true")

        out("[STEP] SELinux etiketleri")
        sh(client,
           "sudo which semanage >/dev/null 2>&1 || sudo {pm} -y install policycoreutils-python-utils policycoreutils-python || true".format(
               pm=pm))
        sh(client,
           f"sudo semanage fcontext -a -t postgresql_db_t '{data_dir}(/.*)?' || sudo semanage fcontext -m -t postgresql_db_t '{data_dir}(/.*)?' || true")
        sh(client, f"sudo restorecon -Rv {data_dir} || true")
        if wal_dir:
            sh(client,
               f"sudo semanage fcontext -a -t postgresql_db_t '{wal_dir}(/.*)?' || sudo semanage fcontext -m -t postgresql_db_t '{wal_dir}(/.*)?' || true")
            sh(client, f"sudo restorecon -Rv {wal_dir} || true")

        code, out_has, _ = ssh_exec(client,
                                    f"sh -lc 'test -s {shlex.quote(data_dir)}/PG_VERSION && echo hasdb || echo empty'")
        has_db = (out_has.strip() == "hasdb")

        locale_opt = f" --locale={shlex.quote(locale)}" if locale else ""

        out("[STEP] Systemd drop-in ile PGDATA override")
        sh(client, f"sudo install -d -m 0755 /etc/systemd/system/{service_name}.service.d")
        sh(client,
           f"printf '%s\n' '[Service]' 'Environment=PGDATA={shlex.quote(data_dir)}' | sudo tee /etc/systemd/system/{service_name}.service.d/override.conf >/dev/null")
        sh(client, f"sudo sed -n '1,120p' /etc/systemd/system/{service_name}.service.d/override.conf || true")
        sh(client, "sudo systemctl daemon-reload || true")
        sh(client, f"sudo systemctl reset-failed {service_name} || true")

        if not has_db:
            out("[STEP] initdb")
            if initdb_needs_custom:
                init_cmd = f"sudo -u postgres {bin_prefix}/initdb -D {shlex.quote(data_dir)} -E UTF8 --lc-collate=en_US.UTF-8 --lc-ctype=en_US.UTF-8{locale_opt}"
                if wal_dir: init_cmd += f" -X {shlex.quote(wal_dir)}"
                if not sh(client, init_cmd):
                    client.close();
                    return False, "initdb başarısız."
            else:
                if not sh(client, f"sudo {bin_prefix}/postgresql-{final_ver}-setup initdb"):
                    sh(client,
                       f"sudo -u postgres {bin_prefix}/initdb -D {shlex.quote(default_data)} -E UTF8 --lc-collate=en_US.UTF-8 --lc-ctype=en_US.UTF-8{locale_opt}")
        else:
            raw("[INFO] Mevcut cluster bulundu, initdb atlandı")

        sh(client, f"sudo -u postgres mkdir -p {data_dir}/log || true")
        sh(client, f"sudo chown -R postgres:postgres {data_dir}/log || true")

        out("[STEP] postgresql.conf bulunuyor")
        conf_path = f"{data_dir}/postgresql.conf"
        code, o, _ = ssh_exec(client, f"test -f {shlex.quote(data_dir)}/postgresql.conf && echo ok || echo no")
        if o.strip() != "ok":
            code, o2, _ = ssh_exec(client, "sudo -u postgres psql -Atqc \"SHOW config_file;\"")
            if o2.strip(): conf_path = o2.strip()
        if not conf_path:
            client.close();
            return False, "config_file alınamadı."

        out(f"[STEP] Port {db_port} ayarlanıyor")
        if not sh(client, f"sudo sed -i 's/^#\\?port\\s*=\\s*.*/port = {db_port}/' {shlex.quote(conf_path)}"):
            client.close();
            return False, "Port ayarı yapılamadı."

        out("[CHECK] Port dinleme & binary")
        check_cmd = (
                        "pid=$(ss -ltnp | awk -v p=':%s$' "
                        "'$4 ~ p && /postgres/ {for (i=1;i<=NF;i++) if ($i ~ /pid=/) {sub(\"pid=\",\"\",$i); split($i,a,\",\"); print a[1]; break}}' | head -1); "
                        "if [ -n \"$pid\" ]; then exe=$(readlink -f /proc/$pid/exe); echo $pid $exe; fi"
                    ) % (db_port,)
        code, o3, _ = ssh_exec(client, f"sh -lc {shlex.quote(check_cmd)}")
        if o3.strip():
            parts = o3.strip().split()
            pid = parts[0] if parts else "?"
            exe = parts[1] if len(parts) > 1 else "?"
            raw(f"[INFO] Port {db_port} zaten dinleniyor → PID={pid}, exe={exe}")
            if exe.startswith(bin_prefix):
                raw(f"[OK] Beklenen path: {bin_prefix}")
            else:
                raw(f"[WARN] Farklı path (beklenen: {bin_prefix})")
            client.close()
            return True, "Port meşgul; mevcut Postgres bulundu."

        out("[STEP] Servis enable/start")
        if not sh(client, f"sudo systemctl enable --now {service_name}"):
            sh(client, f"sudo systemctl status {service_name} --no-pager || true")
            sh(client, f"sudo journalctl -u {service_name} -n 100 --no-pager || true")
            sh(client, f"sudo chown -R postgres:postgres {data_dir} || true")
            sh(client, f"sudo chmod 700 {data_dir} || true")
            sh(client, f"sudo -u postgres mkdir -p {data_dir}/log || true")
            sh(client, f"sudo chown -R postgres:postgres {data_dir}/log || true")
            sh(client, f"sudo restorecon -Rv {data_dir} || true")
            if wal_dir: sh(client, f"sudo restorecon -Rv {wal_dir} || true")
            is_busy = ("if ss -ltn | awk '{print $4}' | grep -q \":%s$\"; then echo busy; fi") % (db_port,)
            code, busy_out, _ = ssh_exec(client, f"bash -lc {shlex.quote(is_busy)}")
            if "busy" in busy_out:
                find_free_port = (
                    "pick=''; for p in $(seq 5433 5450); do ss -ltn | awk '{print $4}' | grep -q \":\"$p\"$\" || { pick=$p; break; }; done; if [ -n \"$pick\" ]; then echo $pick; fi"
                )
                code, free_p, _ = ssh_exec(client, f"bash -lc {shlex.quote(find_free_port)}")
                new_port = free_p.strip()
                if new_port:
                    raw(f"[INFO] Port {db_port} meşgul → {new_port} yapılıyor")
                    sh(client, f"sudo sed -i 's/^#\\?port\\s*=\\s*.*/port = {new_port}/' {shlex.quote(conf_path)}")
                    db_port = int(new_port)
            sh(client, f"sudo systemctl daemon-reload || true")
            if not sh(client, f"sudo systemctl restart {service_name}"):
                startup_log = f"{data_dir}/startup.log"
                sh(client, f"sudo -u postgres {bin_prefix}/pg_ctl -D {data_dir} -l {startup_log} start || true")
                sh(client, f"tail -n 200 {startup_log} || true")
                code, _, _ = ssh_exec(client, f"sudo systemctl is-active --quiet {service_name}")
                if code != 0:
                    client.close()
                    return False, "Servis başlatma başarısız."

        out("[STEP] Servisin hazır olması bekleniyor")
        ready = False
        for _ in range(90):
            code, _, _ = ssh_exec(client,
                                  f"sudo -u postgres -H bash -lc \"{bin_prefix}/psql -p {db_port} -Atqc 'SELECT 1;'\"")
            if code == 0: ready = True; break
            ssh_exec(client, "sleep 1")
        if not ready:
            sh(client, f"sudo systemctl status {service_name} --no-pager || true")
            sh(client, f"sudo journalctl -u {service_name} -n 200 --no-pager || true")
            latest_tail = f"latest=$(ls -1t {shlex.quote(data_dir)}/log/* 2>/dev/null | head -1); if [ -n \"$latest\" ]; then tail -n 200 \"$latest\"; fi"
            sh(client, f"bash -lc {shlex.quote(latest_tail)}")
            client.close();
            return False, "PostgreSQL servis hazır hale gelmedi."

        out("[STEP] postgres şifresi ayarlanıyor")
        pw_sql = db_superuser_password.replace("'", "''")
        set_pwd_cmd = (
            f"sudo -u postgres -H bash -lc "
            f"\"{bin_prefix}/psql -p {db_port} -Atqc \\\"ALTER USER postgres WITH PASSWORD '{pw_sql}';\\\"\""
        )
        if not sh(client, set_pwd_cmd):
            client.close()
            return False, "postgres şifresi ayarlanamadı."

        # ===== HBA (append / upsert / replace_all / managed_block) =====
        if hba_apply:
            code, o4, _ = ssh_exec(client,
                                   f"sudo -u postgres -H bash -lc \"{bin_prefix}/psql -p {db_port} -Atqc 'SHOW hba_file;'\"")
            hba_path = o4.strip() or f"{data_dir}/pg_hba.conf"
            raw(f"[INFO] hba_file: {hba_path}")

            mode = (hba_mode or "upsert").strip().lower()
            sh(client, f"sudo cp -a {shlex.quote(hba_path)} {shlex.quote(hba_path)}.$(date +%Y%m%d%H%M%S).bak || true")

            # RAW ise (sadece append/managed_block)
            if hba_bulk_raw and (hba_bulk or "").strip() and mode in ("append", "managed_block"):
                tmp = "/tmp/hba_bulk_raw.txt"
                if not upload_text_tmp(client, hba_bulk or "", tmp):
                    client.close();
                    return False, "RAW içerik yüklenemedi."
                if mode == "append":
                    cmd = (
                        "sudo bash -lc "
                        f"\"printf '\\n# added by installer %s\\n' \\\"$(date '+%F %T')\\\" >> {shlex.quote(hba_path)}; "
                        f"cat {shlex.quote(tmp)} >> {shlex.quote(hba_path)}; "
                        f"rm -f {shlex.quote(tmp)}; "
                        f"chown postgres:postgres {shlex.quote(hba_path)}; chmod 600 {shlex.quote(hba_path)}\""
                    )
                    if not sh(client, cmd): client.close(); return False, "pg_hba.conf append (RAW) başarısız."
                else:
                    begin = "# BEGIN managed by installer"
                    end = "# END managed by installer"
                    timestamp = datetime.now().strftime('%F %T')
                    cmd = (
                        "sudo bash -lc "
                        f"\"sed -i '/^{begin}$/,/^{end}$/d' {shlex.quote(hba_path)} || true; "
                        f"echo '{begin}' | tee -a {shlex.quote(hba_path)} >/dev/null; "
                        f"echo '# {timestamp}' | tee -a {shlex.quote(hba_path)} >/dev/null; "
                        f"cat {shlex.quote(tmp)} | tee -a {shlex.quote(hba_path)} >/dev/null; "
                        f"echo '{end}' | tee -a {shlex.quote(hba_path)} >/dev/null; "
                        f"rm -f {shlex.quote(tmp)}; "
                        f"chown postgres:postgres {shlex.quote(hba_path)}; chmod 600 {shlex.quote(hba_path)}\""
                    )
                    if not sh(client, cmd): client.close(); return False, "pg_hba.conf managed_block (RAW) başarısız."

            else:
                # Kuralları parse edip normalize ederek uygula
                rules = []
                if hba_bulk and hba_bulk.strip():
                    rules = _parse_hba_bulk(hba_bulk)
                    if not rules:
                        raw("[WARN] rh_hba_bulk formatı boş/yanlış; tekli alanlara düşülecek.")
                if not rules:
                    _type = (hba_type or "local").strip().lower()
                    if _type not in ("local", "host"): _type = "local"
                    _db = _sanitize_csv(hba_db);
                    _user = _sanitize_csv(hba_user)
                    _method_n = _norm_method(hba_method, _type)
                    _addr = None
                    if _type == "host":
                        choice = (hba_addr_sel or "127.0.0.1/32").strip()
                        _addr = (hba_addr_custom or "127.0.0.1/32").strip() if choice == "custom" else choice
                    rules = [{"type": _type, "db": _db, "user": _user, "addr": _addr, "method": _method_n}]

                managed_lines: List[str] = []
                for rule in rules:
                    t = rule["type"]
                    rule["method"] = _norm_method(rule["method"], t)
                    line = _hba_line_from_rule(rule)
                    raw(f"[INFO] Hedef kural: {line}")

                    if mode == "append":
                        cmd = (
                            f"sudo bash -lc \"if ! grep -Fxq {shlex.quote(line)} {shlex.quote(hba_path)} 2>/dev/null; then "
                            f"printf '\\n# added by installer %s\\n{line}\\n' \\\"$(date '+%F %T')\\\" | tee -a {shlex.quote(hba_path)} >/dev/null; "
                            f"chown postgres:postgres {shlex.quote(hba_path)}; chmod 600 {shlex.quote(hba_path)}; fi\""
                        )
                        if not sh(client, cmd): client.close(); return False, "pg_hba.conf append başarısız."

                    elif mode == "upsert":
                        if t == "local":
                            awk_script = (
                                    "BEGIN{repl=0}\n"
                                    "/^[ \\t]*#/ {print; next}\n"
                                    f"NF>=4 && $1==\\\"local\\\" && $2==\\\"{rule['db']}\\\" && $3==\\\"{rule['user']}\\\" "
                                    "{{ $4=\\\"" + rule["method"] + "\\\"; repl=1; print; next }}\n"
                                                                    "{print}\n"
                                                                    f"END{{ if(!repl) print \\\"local {rule['db']} {rule['user']} {rule['method']}\\\" }}\n"
                            )
                        else:
                            addr = rule.get("addr") or "127.0.0.1/32"
                            awk_script = (
                                    "BEGIN{repl=0}\n"
                                    "/^[ \\t]*#/ {print; next}\n"
                                    f"NF>=5 && $1==\\\"host\\\" && $2==\\\"{rule['db']}\\\" && $3==\\\"{rule['user']}\\\" && $4==\\\"{addr}\\\" "
                                    "{{ $5=\\\"" + rule["method"] + "\\\"; repl=1; print; next }}\n"
                                                                    "{print}\n"
                                                                    f"END{{ if(!repl) print \\\"host {rule['db']} {rule['user']} {addr} {rule['method']}\\\" }}\n"
                            )
                        upsert_cmd = (
                                "sudo bash -lc "
                                "\"cat > /tmp/hba_upsert.awk << 'AWK'\n" +
                                awk_script.replace("\\", "\\\\").replace("\"", "\\\"") +
                                "AWK\n"
                                f"awk -f /tmp/hba_upsert.awk {shlex.quote(hba_path)} > /tmp/hba_new && "
                                f"cat /tmp/hba_new > {shlex.quote(hba_path)} && rm -f /tmp/hba_new /tmp/hba_upsert.awk; "
                                f"chown postgres:postgres {shlex.quote(hba_path)}; chmod 600 {shlex.quote(hba_path)}\""
                        )
                        if not sh(client, upsert_cmd): client.close(); return False, "pg_hba.conf upsert başarısız."

                    elif mode == "replace_all":
                        if t == "local":
                            pat = f"^\\s*local\\s+{rule['db']}\\s+{rule['user']}\\s+"
                        else:
                            addr = (rule.get("addr") or "127.0.0.1/32").replace("/", "\\/")
                            pat = f"^\\s*host\\s+{rule['db']}\\s+{rule['user']}\\s+{addr}\\s+"
                        replace_cmd = (
                            "sudo bash -lc "
                            f"\"sed -i -E 's@({pat})@# replaced $(date +%F\\ %T) \\1@' {shlex.quote(hba_path)} || true; "
                            f"grep -Fxq {shlex.quote(line)} {shlex.quote(hba_path)} || "
                            f"echo -e '\\n# added by installer $(date +%F\\ %T)\\n{line}' | tee -a {shlex.quote(hba_path)} >/dev/null; "
                            f"chown postgres:postgres {shlex.quote(hba_path)}; chmod 600 {shlex.quote(hba_path)}\""
                        )
                        if not sh(client,
                                  replace_cmd): client.close(); return False, "pg_hba.conf replace_all başarısız."

                    elif mode == "managed_block":
                        managed_lines.append(line)
                    else:
                        client.close();
                        return False, f"Bilinmeyen hba_mode: {mode}"

                if mode == "managed_block":
                    begin = "# BEGIN managed by installer"
                    end = "# END managed by installer"
                    timestamp = datetime.now().strftime('%F %T')
                    joined = "\\n".join(managed_lines)
                    managed_cmd = (
                        "sudo bash -lc "
                        f"\"sed -i '/^{begin}$/,/^{end}$/d' {shlex.quote(hba_path)} || true; "
                        f"echo '{begin}' | tee -a {shlex.quote(hba_path)} >/dev/null; "
                        f"echo '# {timestamp}' | tee -a {shlex.quote(hba_path)} >/dev/null; "
                        f"printf '%s\\n' \\\"{joined}\\\" | tee -a {shlex.quote(hba_path)} >/dev/null; "
                        f"echo '{end}' | tee -a {shlex.quote(hba_path)} >/dev/null; "
                        f"chown postgres:postgres {shlex.quote(hba_path)}; chmod 600 {shlex.quote(hba_path)}\""
                    )
                    if not sh(client,
                              managed_cmd): client.close(); return False, "pg_hba.conf managed_block (normalize) başarısız."

            sh(client,
               f"sudo -u postgres -H bash -lc \"{bin_prefix}/psql -p {db_port} -Atqc 'SELECT pg_reload_conf();'\"")
            raw("[INFO] pg_hba.conf değişiklikleri yüklendi (pg_reload_conf).")

        # Apply PostgreSQL configuration if provided
        if postgresql_config:
            out("[STEP] PostgreSQL konfigürasyonu uygulanıyor...")
            try:
                # Parse configuration lines
                config_lines = []
                for line in postgresql_config.split('\n'):
                    line = line.strip()
                    if line and not line.startswith('#'):
                        config_lines.append(line)

                # Apply each setting via SSH
                for config_line in config_lines:
                    key_value = config_line.split('=', 1)
                    if len(key_value) == 2:
                        key = key_value[0].strip()
                        value = key_value[1].strip()

                        # Update existing setting
                        sh(client, f"sudo sed -i 's/^#\\?{key}\\s*=.*/{key} = {value}/' {shlex.quote(conf_path)}")

                        # Add setting if not exists
                        sh(client,
                           f"sudo grep -q '^{key}\\s*=' {shlex.quote(conf_path)} || echo '{key} = {value}' | sudo tee -a {shlex.quote(conf_path)} >/dev/null")

                # Set proper ownership and permissions
                sh(client,
                   f"sudo chown postgres:postgres {shlex.quote(conf_path)} && sudo chmod 600 {shlex.quote(conf_path)}")

                out(f"[OK] {len(config_lines)} konfigürasyon ayarı uygulandı")

                # Restart PostgreSQL service
                out("[STEP] PostgreSQL servisi yeniden başlatılıyor...")
                if sh(client, f"sudo systemctl restart {service_name}"):
                    out("[OK] Servis yeniden başlatıldı")
                else:
                    out("[WARN] Servis yeniden başlatılamadı")

            except Exception as ex:
                out(f"[WARN] Konfigürasyon uygulanamadı: {ex}")

        # Install extensions if selected
        if extensions:
            out("[STEP] PostgreSQL Extension'ları kuruluyor...")
            try:
                # Check if EPEL is available for some extensions
                out("EPEL repository kontrol ediliyor...")
                sh(client, f"sudo {pm} -y install epel-release || true")
                sh(client, f"sudo {pm} -y makecache || true")
                # Extension package mapping for RedHat systems
                extension_packages = {
                    "extension_pgaudit": [f"postgresql{final_ver}-pgaudit", f"pgaudit{final_ver}", "pgaudit",
                                          "postgresql-pgaudit"],
                    "extension_postgres_fdw": [f"postgresql{final_ver}-contrib"],  # Built-in
                    "extension_oracle_fdw": [f"postgresql{final_ver}-oracle-fdw", f"oracle-fdw{final_ver}",
                                             "oracle-fdw"],
                    "extension_tds_fdw": [f"postgresql{final_ver}-tds-fdw", f"tds-fdw{final_ver}", "tds-fdw"],
                    "extension_mysql_fdw": [f"postgresql{final_ver}-mysql-fdw", f"mysql-fdw{final_ver}", "mysql-fdw"],
                    "extension_pg_stat_statements": [f"postgresql{final_ver}-contrib"],  # Built-in
                    "extension_pg_cron": [f"postgresql{final_ver}-cron", f"pg-cron{final_ver}", "pg-cron"],
                    "extension_uuid_ossp": [f"postgresql{final_ver}-contrib"],  # Built-in
                    "extension_hstore": [f"postgresql{final_ver}-contrib"],  # Built-in
                    "extension_ltree": [f"postgresql{final_ver}-contrib"],  # Built-in
                }

                # Extension names for CREATE EXTENSION
                extension_names = {
                    "extension_pgaudit": "pgaudit",
                    "extension_postgres_fdw": "postgres_fdw",
                    "extension_oracle_fdw": "oracle_fdw",
                    "extension_tds_fdw": "tds_fdw",
                    "extension_mysql_fdw": "mysql_fdw",
                    "extension_pg_stat_statements": "pg_stat_statements",
                    "extension_pg_cron": "pg_cron",
                    "extension_uuid_ossp": "uuid-ossp",
                    "extension_hstore": "hstore",
                    "extension_ltree": "ltree",
                }

                selected_extensions = [ext for ext, selected in extensions.items() if selected]
                if selected_extensions:
                    out(f"Seçilen extension'lar: {', '.join(selected_extensions)}")

                    # Install packages
                    for ext in selected_extensions:
                        if ext in extension_packages:
                            package_list = extension_packages[ext]
                            if isinstance(package_list, list):
                                # Try each package name until one works
                                package_installed = False
                                for package in package_list:
                                    out(f"Paket deneniyor: {package}")
                                    code, _, _ = ssh_exec(client, f"sudo {pm} -y install {package}")
                                    if code == 0:
                                        out(f"[OK] Paket kuruldu: {package}")
                                        package_installed = True
                                        break
                                    else:
                                        out(f"[SKIP] Paket bulunamadı: {package}")

                                if not package_installed:
                                    out(f"[WARN] Hiçbir paket kurulamadı: {ext}")
                            else:
                                # Single package (backward compatibility)
                                sh(client, f"sudo {pm} -y install {package_list} || true")

                    # Create extensions in database if auto_create is enabled
                    if extension_auto_create:
                        out("Extension'lar veritabanında aktifleştiriliyor...")
                        for ext in selected_extensions:
                            if ext in extension_names:
                                ext_name = extension_names[ext]
                                out(f"CREATE EXTENSION {ext_name} çalıştırılıyor...")
                                create_ext_cmd = (
                                    f"sudo -u postgres -H bash -lc "
                                    f"\"{bin_prefix}/psql -p {db_port} -Atqc \\\"CREATE EXTENSION IF NOT EXISTS {ext_name};\\\"\""
                                )
                                sh(client, create_ext_cmd)

                    out("Extension kurulumu tamamlandı.")
                else:
                    out("Extension seçilmedi.")

            except Exception as ex:
                out(f"[WARN] Extension kurulumu başarısız: {ex}")

        client.close()
        out("[DONE] Kurulum tamam.")
        return True, "\n".join(outputs)

    except Exception as ex:
        try:
            client.close()
        except Exception:
            pass
        out(f"[EXC] {ex}")
        return False, str(ex)


# ====================== Flask Rotaları ======================

@app.route("/", methods=["GET"])
def index():
    return render_template_string(FORM_HTML)

@app.route("/pg_install", methods=["GET"])
def pg_install():
    return render_template_string(FORM_HTML)


@app.route("/prepare_install", methods=["POST"])
def prepare_install():
    _cleanup_payloads()
    data = request.form.to_dict(flat=True)
    token = _store_payload(data)
    return jsonify({"token": token})


def sse_format(data: str):
    for line in (data or "").splitlines():
        yield f"data: {line}\n"
    yield "\n"


@app.route("/install_stream", methods=["GET"])
def install_stream():
    """
    SSE ile canlı kurulum. Büyük içerikler için önce /prepare_install (POST),
    ardından burada token ile devam edilir.
    """
    token = request.args.get("token", "").strip()
    if token:
        payload = _get_payload(token)
        if not payload:
            return Response(stream_with_context(sse_format("[ERR] Geçersiz/bitmiş token.")),
                            mimetype="text/event-stream")
        args = payload
    else:
        args = request.args.to_dict(flat=True)

    target_os = detect_os(args.get("target_os", "auto"))
    pg_version = (args.get("pg_version") or "").strip() or None
    port = int(args.get("port", "5432"))
    superuser_password = args.get("superuser_password", "")
    locale = (args.get("locale") or "").strip() or None
    install_all_components = bool(args.get("install_all_components", ""))

    # Parse component selection
    components = {}
    for key, value in args.items():
        if key.startswith("component_"):
            components[key] = bool(value)

    # Parse extension selection
    extensions = {}
    for key, value in args.items():
        if key.startswith("extension_"):
            extensions[key] = bool(value)

    extension_auto_create = bool(args.get("extension_auto_create", ""))

    win_installer_url = (args.get("win_installer_url") or "").strip()
    win_prefix = args.get("win_prefix", r"C:\\Program Files\\PostgreSQL\\16")
    win_datadir = args.get("win_datadir", r"C:\\PostgreSQL\\data")
    win_servicename = args.get("win_servicename", "postgresql-x64-16")

    # PostgreSQL configuration
    postgresql_config = args.get("postgresql_config")

    rh = dict(
        ssh_host=(args.get("ssh_host") or "").strip(),
        ssh_user=(args.get("ssh_user") or "root").strip(),
        ssh_port=int(args.get("ssh_port") or 22),
        ssh_auth_type=(args.get("ssh_auth_type") or "password").strip(),
        ssh_password=args.get("ssh_password"),
        ssh_key=args.get("ssh_key"),
        rh_data_dir=(args.get("rh_data_dir") or "").strip() or None,
        rh_wal_dir=(args.get("rh_wal_dir") or "").strip() or None,
        hba_apply=bool(args.get("rh_hba_apply", "")),
        hba_type=(args.get("rh_hba_type") or "local").strip(),
        hba_addr_sel=(args.get("rh_hba_addr_sel") or "127.0.0.1/32").strip(),
        hba_addr_custom=(args.get("rh_hba_addr_custom") or "").strip(),
        hba_db=(args.get("rh_hba_db") or "all").strip(),
        hba_user=(args.get("rh_hba_user") or "all").strip(),
        hba_method=(args.get("rh_hba_method") or "scram-sha-256").strip(),
        hba_mode=(args.get("rh_hba_mode") or "upsert").strip(),
        hba_bulk=(args.get("rh_hba_bulk") or "").strip(),
        hba_bulk_raw=bool(args.get("rh_hba_bulk_raw", "")),
        package_manager=(args.get("rh_package_manager") or "auto").strip(),
    )

    q: "queue.Queue[str]" = queue.Queue()
    done = {"status": None}

    def emit(line: str):
        q.put(line)

    def worker():
        try:
            emit(f"[INFO] Kurulum başlatılıyor - OS: {target_os}")

            if target_os == "windows":
                emit("[INFO] Windows sessiz kurulum başlıyor...")
                ok, _ = windows_install_with_edb_silent(
                    installer_url=win_installer_url,
                    prefix=win_prefix,
                    datadir=win_datadir,
                    servicename=win_servicename,
                    password=superuser_password,
                    port=port,
                    locale=locale,
                    postgresql_config=postgresql_config,
                    emit=emit
                )
                done["status"] = "success" if ok else "error"

            elif target_os == "linux":
                emit("[INFO] Debian/Ubuntu kurulum başlıyor...")
                if not is_admin():
                    emit("[WARN] Root yetkisi yoksa bazı adımlar başarısız olabilir.")
                ok, _ = linux_install_with_apt(
                    port=port,
                    password=superuser_password,
                    locale=locale,
                    datadir=(args.get("linux_datidir") or args.get("linux_datadir") or "").strip() or None,
                    pg_version=pg_version,
                    install_all_components=install_all_components,
                    components=components,
                    postgresql_config=postgresql_config,
                    emit=emit
                )
                done["status"] = "success" if ok else "error"

            elif target_os == "redhat":
                emit("[INFO] RHEL/Alma/Rocky kurulum başlıyor...")
                ok, _ = redhat_install_over_ssh(
                    ssh_host=rh["ssh_host"],
                    ssh_user=rh["ssh_user"],
                    ssh_port=rh["ssh_port"],
                    auth_type=rh["ssh_auth_type"],
                    ssh_password=rh["ssh_password"],
                    ssh_key=rh["ssh_key"],
                    db_port=port,
                    db_superuser_password=superuser_password,
                    locale=locale,
                    pg_version=pg_version,
                    custom_data_dir=rh["rh_data_dir"],
                    custom_wal_dir=rh["rh_wal_dir"],
                    hba_apply=rh["hba_apply"],
                    hba_type=rh["hba_type"],
                    hba_addr_sel=rh["hba_addr_sel"],
                    hba_addr_custom=rh["hba_addr_custom"],
                    hba_db=rh["hba_db"],
                    hba_user=rh["hba_user"],
                    hba_method=rh["hba_method"],
                    hba_mode=rh["hba_mode"],
                    hba_bulk=rh["hba_bulk"],
                    hba_bulk_raw=rh["hba_bulk_raw"],
                    install_all_components=install_all_components,
                    components=components,
                    postgresql_config=postgresql_config,
                    package_manager=rh["package_manager"],
                    extensions=extensions,
                    extension_auto_create=extension_auto_create,
                    emit=emit
                )
                done["status"] = "success" if ok else "error"
            else:
                emit(f"[ERR] Desteklenmeyen OS: {target_os}")
                done["status"] = "error"
        except Exception as ex:
            emit(f"[EXC] Genel kurulum hatası: {str(ex)}")
            done["status"] = "error"
        finally:
            q.put(f"STATUS: {done['status'] or 'error'}")

    threading.Thread(target=worker, daemon=True).start()

    def stream():
        yield from sse_format("Kurulum başlatıldı...")
        while True:
            line = q.get()
            yield from sse_format(line)
            if line.startswith("STATUS:"):
                break

    resp = Response(stream_with_context(stream()), mimetype="text/event-stream")
    resp.headers["Cache-Control"] = "no-cache"
    resp.headers["Connection"] = "keep-alive"
    resp.headers["X-Accel-Buffering"] = "no"
    return resp


@app.route("/install", methods=["POST"])
def install_legacy():
    target_os = detect_os(request.form.get("target_os", "auto"))
    return render_template_string(RESULT_HTML,
                                  logs=f"Bu uç kapalı. Lütfen canlı kurulum için ana sayfayı kullanın.\nSeçilen OS: {target_os}")


# ====================== App ======================

if __name__ == "__main__":
    port = int(os.environ.get("APP_PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True, use_reloader=False)
