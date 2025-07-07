<h1 align="center">🕶️ cakancoli</h1>
<p align="center"><b>Modular Recon & OSINT Framework - Powered by CyberHeroes</b></p>
<p align="center">
  <img src="https://img.shields.io/badge/status-active-success?style=flat-square" />
  <img src="https://img.shields.io/badge/language-python-blue?style=flat-square" />
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" />
</p>

---

## 📌 Deskripsi

**cakancoli** adalah framework pengintaian otomatis yang mampu melakukan pemetaan permukaan serangan terhadap domain target. Terdiri dari 30+ modul modular, framework ini dirancang untuk profesional keamanan siber, red team, bug hunter, dan pentester yang mengutamakan efisiensi dan taktik.

---

## ⚙️ Fitur Utama

| 🔍 Fitur Recon | ✅ Status | 📝 Keterangan |
|---------------|-----------|---------------|
| WHOIS Pasif | ✅ | Deteksi informasi domain tanpa kueri aktif |
| WAF Fingerprint | ✅ | Deteksi perlindungan firewall otomatis |
| Subdomain Finder | ✅ | Crawl & passive recon subdomain |
| Email Leak Checker | ✅ | Pencocokan email dengan database breach |
| GitHub Dorking | ✅ | Temukan secrets di repo publik |
| ASN & Reverse IP | ✅ | Analisa rentang IP & domain se-IP |
| CMS Detector | ✅ | WordPress, Joomla, Drupal |
| Open Redirect Scanner | ✅ | Cek parameter `url=`, `next=` yang vulnerable |
| JS Endpoint Parser | ✅ | Temukan URL/API tersembunyi |
| TLS Cert Spotter | ✅ | Pemetaan sertifikat TLS/SSL publik |
| DNS Zone Transfer | ✅ | Deteksi misconfig nameserver |
| Directory Bruteforce | ✅ | Pemindaian direktori sensitif |
| Login Page Sniper | ✅ | Deteksi halaman login & dashboard |
| CORS Misconfig Check | ✅ | Periksa kelemahan CORS |
| Auto XSS Payload Tester | ✅ | Coba payload XSS dasar secara otomatis |

> 💡 Dan masih banyak lagi hingga total **30+ module aktif**.

---

## 🚀 Cara Instalasi & Penggunaan

### 1. Clone Repo
```bash
git clone https://github.com/yourname/cakancoli.git
cd cakancoli
```

2. Install Dependensi
```
pip install -r requirements.txt
```
> 3. Siapkan File Pendukung
> user_agents.txt → User-Agent acak
> proxies.txt → Proxy http/https
> common.txt → Wordlist path + file .js

---

📈 Contoh Output
```
[
  {
    "whois": ["Registry Expiry Date: 2026-01-01T00:00:00Z"]
  },
  {
    "subdomains": ["dev.contoh.com", "api.contoh.com"]
  },
  {
    "waf": "Ditemukan WAF: Cloudflare"
  }
]
```
---

## ⚠️ Disclaimer

> Framework ini dibuat hanya untuk pembelajaran, riset keamanan, dan pentesting yang legal.
Gunakan hanya pada sistem milik sendiri atau yang telah mendapatkan izin eksplisit.

