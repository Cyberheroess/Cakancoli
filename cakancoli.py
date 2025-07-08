
import requests, socket, re, json, asyncio, aiohttp, threading, subprocess, os, random, time
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from dns import resolver, exception
from datetime import datetime

M  = "\033[91m"   
H  = "\033[92m"   
K  = "\033[93m"   
B  = "\033[94m"   
C  = "\033[96m"   
W  = "\033[97m"   
def rgb(r, g, b):
        return f"\033[38;2;{r};{g};{b}m"

RESET = "\033[0m"

def logo():
    print(rgb(255, 0, 0) + "   ____  _                           _ _ ")
    print(rgb(255, 165, 0) + "  / __ \| | ____ _ _ __     ___ ___ | (_)")
    print(rgb(255, 255, 0) + " / / _` | |/ / _` | '_ \   / __/ _ \| | |")
    print(rgb(0, 255, 0) + "| | (_| |   < (_| | | | | | (_| (_) | | |")
    print(rgb(0, 255, 255) + " \ \__,_|_|\_\__,_|_| |_|  \___\___/|_|_|")
    print(rgb(0, 128, 255) + "  \____/                                 ")

    print("""jangan berpikir aneh melihat logo nya, ini maha karya by saldy
    
          """)
    print(RESET)
print(logo())



with open("user_agents.txt", "r") as f:
    USER_AGENTS = [ua.strip() for ua in f.readlines()]

with open("proxies.txt", "r") as f:
    PROXIES = [{"http": p.strip(), "https": p.strip()} for p in f.readlines()]

with open("common.txt", "r") as f:
    WORDLIST = [w.strip() for w in f.readlines()]

HEADERS = lambda: {
    "User-Agent": random.choice(USER_AGENTS),
    "Accept": "*/*",
    "Connection": "keep-alive"
}

PROXY = lambda: random.choice(PROXIES)

LOGS = []

class siWhoisPasif:
    def jalan(self, domain):
        try:
            print(f"{C}[*] siWhoisPasif: Mengambil data WHOIS dari {domain} ...{RESET}")
            whois_url = f"https://www.whois.com/whois/{domain}"
            res = requests.get(whois_url, headers=HEADERS(), proxies=PROXY(), timeout=12)

            # Ambil blok WHOIS utama
            raw = re.findall(r"(?<=<pre class=\"df-raw\" id=\"registryData\">)(.*?)(?=</pre>)", res.text, re.DOTALL)
            if not raw:
                print(f"{M}[!] siWhoisPasif: Gagal menemukan blok WHOIS utama dari HTML.{RESET}")
                return

            data = raw[0].strip().splitlines()
            whois_data = {}

            for line in data:
                if ":" in line:
                    key, value = line.split(":", 1)
                    key = key.strip().lower()
                    value = value.strip()
                    if key in whois_data:
                        if isinstance(whois_data[key], list):
                            whois_data[key].append(value)
                        else:
                            whois_data[key] = [whois_data[key], value]
                    else:
                        whois_data[key] = value

            penting = {
                "domain name": whois_data.get("domain name", "N/A"),
                "registrar": whois_data.get("registrar", "N/A"),
                "name server": whois_data.get("name server", []),
                "status": whois_data.get("status", "N/A"),
                "creation date": whois_data.get("creation date", "N/A"),
                "expiration date": whois_data.get("registry expiry date", "N/A"),
                "org": whois_data.get("registrant organization", "N/A"),
                "country": whois_data.get("registrant country", "N/A")
            }

            LOGS.append({"whois_detail": penting})

            print(f"{H}[+] siWhoisPasif: Sukses parsing WHOIS - Info penting ditemukan:{RESET}")
            for k, v in penting.items():
                print(f"{B}    {k.capitalize()}:{RESET} {v}")

        except Exception as e:
            print(f"{M}[!] siWhoisPasif: Gagal mengambil WHOIS - {e}{RESET}")

class siShodanKasian:
    def jalan(self, domain):
        try:
            print(f"{B}[*] siShodanKasian: Mencari informasi dari Shodan untuk {domain} ...{RESET}")
            ip = socket.gethostbyname(domain)
            print(f"{C}[i] IP address domain: {ip}{RESET}")
            url = f"https://api.shodan.io/shodan/host/{ip}?key=SHODAN_API_KEY"
            res = requests.get(url, timeout=10)
            hasil = res.json()

            if "error" in hasil:
                print(f"{K}[~] siShodanKasian: Shodan mengembalikan error: {hasil['error']}{RESET}")
                LOGS.append({"shodan": {"ip": ip, "error": hasil.get("error")}})
                return

            result = {
                "ip_str": hasil.get("ip_str", "N/A"),
                "hostname": hasil.get("hostnames", []),
                "org": hasil.get("org", "N/A"),
                "os": hasil.get("os", "N/A"),
                "isp": hasil.get("isp", "N/A"),
                "city": hasil.get("city", "N/A"),
                "country": hasil.get("country_name", "N/A"),
                "ports": [],
                "services": []
            }

            for service in hasil.get("data", []):
                port = service.get("port")
                banner = service.get("data", "").strip().split("\n")[0][:80]
                service_info = {
                    "port": port,
                    "product": service.get("product", "Unknown"),
                    "version": service.get("version", "Unknown"),
                    "banner": banner
                }
                result["ports"].append(port)
                result["services"].append(service_info)

            LOGS.append({"shodan_deep": result})

            print(f"{H}[+] siShodanKasian: Data Shodan berhasil diambil untuk IP {ip}{RESET}")
            print(f"{B}    ▸ Hostname: {RESET}{', '.join(result['hostname'])}")
            print(f"{B}    ▸ ISP / Org: {RESET}{result['isp']} / {result['org']}")
            print(f"{B}    ▸ Lokasi: {RESET}{result['city']}, {result['country']}")
            print(f"{B}    ▸ OS Terdeteksi: {RESET}{result['os']}")
            print(f"{B}    ▸ Port Terbuka: {RESET}{', '.join(map(str, result['ports']))}")

            for svc in result["services"]:
                print(f"{C}       → Port {svc['port']} | {svc['product']} {svc['version']} | Banner: {svc['banner']}{RESET}")

        except Exception as e:
            print(f"{M}[!] siShodanKasian: Gagal mengakses Shodan - {e}{RESET}")
                
class siDNSZoneBomb:
    def jalan(self, domain):
        try:
            print(f"{B}[*] siDNSZoneBomb: Memulai pencarian DNS Zone Transfer untuk {domain} ...{RESET}")
            nameservers = resolver.resolve(domain, 'NS')
            success = False
            for ns in nameservers:
                try:
                    print(f"{C}    [+] Mencoba AXFR ke NS: {ns.target}{RESET}")
                    zone = resolver.zone_for_name(domain, nameserver=str(ns.target))
                    records = zone.nodes.keys()
                    hasil_transfer = []

                    for name in records:
                        rdataset = zone[name]
                        for rdata in rdataset:
                            entry = f"{name.to_text()} {rdata.to_text()}"
                            hasil_transfer.append(entry)

                    LOGS.append({
                        "zone_transfer": {
                            "server": str(ns.target),
                            "records": hasil_transfer
                        }
                    })

                    print(f"{H}[✓] siDNSZoneBomb: Zone Transfer BERHASIL di NS: {ns.target}{RESET}")
                    print(f"{C}    Total record ditemukan: {len(hasil_transfer)}{RESET}")
                    for rec in hasil_transfer[:10]:
                        print(f"{K}      → {rec}{RESET}")
                    
                    success = True
                    break  # tidak perlu cek NS lain kalau sudah sukses

                except Exception as e:
                    print(f"{K}    [-] AXFR gagal di NS {ns.target} - {e}{RESET}")
                    continue

            if not success:
                print(f"{M}[!] siDNSZoneBomb: Semua percobaan AXFR gagal untuk {domain}{RESET}")

        except Exception as e:
            print(f"{M}[!] siDNSZoneBomb: Gagal resolve NS untuk {domain} - {e}{RESET}")
                
class siSubdomainHunter:
    def jalan(self, domain):
        try:
            print(f"{B}[*] siSubdomainHunter: Memulai enumerasi subdomain melalui analisis .js di {domain} ...{RESET}")
            subs = set()
            sumber = {}
            js_files = [f"https://{domain}/{w}" for w in WORDLIST if w.endswith('.js')]

            for js in js_files:
                try:
                    print(f"{C}    [+] Mengambil file JS: {js}{RESET}")
                    r = requests.get(js, headers=HEADERS(), timeout=5)
                    if r.status_code != 200 or "javascript" not in r.headers.get("Content-Type", ""):
                        print(f"{K}      [~] Lewatkan: File bukan JS valid atau status {r.status_code}{RESET}")
                        continue

                    found = re.findall(r"(?:https?://)?([\w\-]+\." + domain.replace(".", r"\.") + ")", r.text, re.IGNORECASE)
                    valid = [f for f in found if f != domain and f.endswith(domain)]
                    if valid:
                        print(f"{H}        [✓] Subdomain ditemukan di {js}: {valid}{RESET}")
                        subs.update(valid)
                        sumber[js] = valid
                    else:
                        print(f"{K}        [~] Tidak ada subdomain di JS ini.{RESET}")

                except Exception as e:
                    print(f"{M}    [-] Gagal ambil {js} - {e}{RESET}")
                    continue

            if subs:
                LOGS.append({
                    "subdomain_hunter": {
                        "total": len(subs),
                        "hasil": list(subs),
                        "sumber_js": sumber
                    }
                })
                print(f"{H}[+] siSubdomainHunter: Total subdomain valid ditemukan: {len(subs)}{RESET}")
                for s in sorted(subs)[:10]:
                    print(f"{C}    → {s}{RESET}")
            else:
                print(f"{K}[~] siSubdomainHunter: Tidak ada subdomain ditemukan di file JS yang dianalisis.{RESET}")

        except Exception as e:
            print(f"{M}[!] siSubdomainHunter: Terjadi kesalahan fatal - {e}{RESET}")
                
class siCorsKocak:
    def jalan(self, domain):
        try:
            print(f"{B}[*] siCorsKocak: Mengecek CORS misconfiguration di https://{domain} ...{RESET}")

            headers = {
                "Origin": "https://evil.com",
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": "X-Custom-Header",
                "User-Agent": random.choice(USER_AGENTS)
            }

            r = requests.options(f"https://{domain}", headers=headers, timeout=8)
            allow_origin = r.headers.get("Access-Control-Allow-Origin", "")
            allow_cred = r.headers.get("Access-Control-Allow-Credentials", "")
            allow_method = r.headers.get("Access-Control-Allow-Methods", "")

            status = "Safe"
            reasons = []

            if allow_origin == "*":
                status = "Vulnerable"
                reasons.append("Wildcard origin ('*') diterima")

            elif "evil.com" in allow_origin.lower():
                status = "Vulnerable"
                reasons.append("Origin 'evil.com' diterima")

            if allow_cred.lower() == "true":
                if allow_origin == "*":
                    status = "Vulnerable"
                    reasons.append("Allow-Credentials 'true' + wildcard origin = bahaya!")
                else:
                    reasons.append("Allow-Credentials aktif")

            if "PUT" in allow_method or "DELETE" in allow_method:
                reasons.append(f"Method sensitif diizinkan: {allow_method}")

            LOGS.append({
                "cors": {
                    "status": status,
                    "origin": allow_origin,
                    "credentials": allow_cred,
                    "methods": allow_method,
                    "reasons": reasons
                }
            })

            if status == "Vulnerable":
                print(f"{H}[✓] CORS MISCONFIGURATION terdeteksi!{RESET}")
                for r in reasons:
                    print(f"{K}    ↳ {r}{RESET}")
            else:
                print(f"{C}[~] CORS terlihat aman (tidak ditemukan misconfig fatal).{RESET}")

        except Exception as e:
            print(f"{M}[!] siCorsKocak: Gagal memeriksa CORS - {e}{RESET}")
                
class siWafDetektor:
    def jalan(self, domain):
        try:
            print(f"{B}[*] siWafDetektor: Mendeteksi kemungkinan keberadaan WAF di https://{domain} ...{RESET}")
            url = f"https://{domain}"
            headers = HEADERS()
            res = requests.get(url, headers=headers, timeout=10)

            fingerprints = {
                "cloudflare": ["cloudflare", "cf-ray", "__cfduid", "cf-cache-status"],
                "sucuri": ["sucuri", "x-sucuri-cache", "x-sucuri-id"],
                "akamai": ["akamai", "akamai-bot-manager", "_abck"],
                "f5": ["f5", "x-waf-status", "bigip"],
                "imperva": ["imperva", "incapsula", "x-cdn", "visid_incap"],
                "aws": ["aws", "aws-waf", "x-amzn-waf-id"],
                "stackpath": ["stackpath", "x-stackpath-"],
                "barracuda": ["barracuda", "barra-counter"]
            }

            deteksi = []
            for waf, tanda in fingerprints.items():
                for t in tanda:
                    if t.lower() in str(res.headers).lower() or t.lower() in res.text.lower():
                        deteksi.append(waf)
                        break  # cukup satu fingerprint per WAF

            if deteksi:
                LOGS.append({
                    "waf_detection": {
                        "detected": True,
                        "fingerprints": list(set(deteksi)),
                        "status_code": res.status_code
                    }
                })
                print(f"{H}[✓] WAF terdeteksi! Jenis yang dicurigai: {', '.join(deteksi)}{RESET}")
            else:
                print(f"{K}[~] Tidak ada fingerprint WAF umum terdeteksi pada {domain}.{RESET}")
                LOGS.append({
                    "waf_detection": {
                        "detected": False,
                        "status_code": res.status_code
                    }
                })

        except Exception as e:
            print(f"{M}[!] siWafDetektor: Error saat memeriksa WAF - {e}{RESET}")
                
class siCDNHeadHunter:
    def jalan(self, domain):
        try:
            print(f"{B}[*] siCDNHeadHunter: Menganalisis kemungkinan penggunaan CDN oleh {domain} ...{RESET}")
            ip = socket.gethostbyname(domain)
            print(f"{C}[+] IP ditemukan: {ip}{RESET}")

            try:
                ping_cmd = ["ping", "-c", "1", domain] if os.name != "nt" else ["ping", "-n", "1", domain]
                ttl_output = subprocess.check_output(ping_cmd).decode()
                ttl_match = re.search(r"ttl[=|:](\d+)", ttl_output, re.IGNORECASE)
                ttl_value = int(ttl_match.group(1)) if ttl_match else None
            except Exception as e:
                ttl_value = None
                print(f"{K}[~] Gagal ambil TTL: {e}{RESET}")

            headers = requests.get(f"https://{domain}", headers=HEADERS(), timeout=8).headers
            cdn_fingerprints = {
                "Cloudflare": ["cf-ray", "cloudflare"],
                "Akamai": ["akamai", "akamai-bot-manager"],
                "Fastly": ["fastly"],
                "StackPath": ["stackpath"],
                "AWS CloudFront": ["cloudfront", "x-amz-cf-id"],
                "Imperva": ["incapsula", "x-cdn"],
                "Google": ["x-goog-meta", "goog"],
            }

            detected = []
            for name, keys in cdn_fingerprints.items():
                for key in keys:
                    if any(key.lower() in h.lower() for h in headers):
                        detected.append(name)
                        break

            cdn_used = bool(detected)
            LOGS.append({
                "cdn_detection": {
                    "ip": ip,
                    "ttl": ttl_value,
                    "cdns": list(set(detected)) if cdn_used else [],
                    "detected": cdn_used
                }
            })

            print(f"{H}[✓] TTL: {ttl_value if ttl_value else 'Tidak tersedia'}{RESET}")
            if cdn_used:
                print(f"{H}[✓] CDN terdeteksi: {', '.join(set(detected))}{RESET}")
            else:
                print(f"{K}[~] Tidak ada CDN umum yang terdeteksi melalui header.{RESET}")

        except Exception as e:
            print(f"{M}[!] siCDNHeadHunter: Error mendeteksi CDN - {e}{RESET}")

class siCmsNinja:
    def jalan(self, domain):
        try:
            print(f"{B}[*] siCmsNinja: Mendeteksi CMS yang digunakan oleh {domain} ...{RESET}")
            url = f"https://{domain}"
            r = requests.get(url, headers=HEADERS(), timeout=10)

            cms_detected = None
            reason = ""

            if "/wp-content/" in r.text or "/wp-includes/" in r.text:
                cms_detected = "WordPress"
                reason = "Ditemukan path /wp-content/"
            elif "Joomla!" in r.text or "com_content" in r.text:
                cms_detected = "Joomla"
                reason = "Konten halaman mengandung 'Joomla!'"
            elif "Drupal.settings" in r.text or "sites/all/" in r.text:
                cms_detected = "Drupal"
                reason = "String 'Drupal.settings' terdeteksi"
            elif "prestashop" in r.text.lower():
                cms_detected = "PrestaShop"
                reason = "String 'prestashop' ditemukan"
            elif "x-magento-vary" in r.headers:
                cms_detected = "Magento"
                reason = "Header 'x-magento-vary' terdeteksi"
            elif "<meta name=\"generator\" content=\"Ghost" in r.text:
                cms_detected = "Ghost"
                reason = "Meta tag Ghost ditemukan"

            soup = BeautifulSoup(r.text, "html.parser")
            generator = soup.find("meta", attrs={"name": "generator"})
            if generator:
                gen_value = generator.get("content", "")
                if not cms_detected:
                    cms_detected = gen_value.split()[0]
                    reason = f"Meta generator: {gen_value}"

            if not cms_detected and "x-powered-by" in r.headers:
                cms_detected = r.headers["x-powered-by"]
                reason = "Header X-Powered-By"

            if cms_detected:
                LOGS.append({
                    "cms": {
                        "detected": cms_detected,
                        "source": reason,
                        "url": url
                    }
                })
                print(f"{H}[✓] CMS Terdeteksi: {cms_detected} ({reason}){RESET}")
            else:
                print(f"{K}[~] CMS tidak dapat dikenali dari konten, meta, atau header.{RESET}")
                LOGS.append({
                    "cms": {
                        "detected": None,
                        "source": "not found",
                        "url": url
                    }
                })

        except Exception as e:
            print(f"{M}[!] siCmsNinja: Error saat mendeteksi CMS - {e}{RESET}")

class siPortManja:
    def jalan(self, domain):
        try:
            print(f"{B}[*] siPortManja: Memulai pemindaian port untuk {domain} ...{RESET}")
            ip = socket.gethostbyname(domain)
            ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 465, 587, 993, 995,
                     8080, 8443, 8888, 3306, 5432, 6379, 9200, 27017]

            hasil_scan = []

            for port in ports:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(2)
                    s.connect((ip, port))

                    try:
                        banner = s.recv(1024).decode(errors="ignore").strip()
                    except:
                        banner = ""

                    status = {
                        "port": port,
                        "status": "open",
                        "banner": banner if banner else "n/a"
                    }
                    hasil_scan.append(status)

                    print(f"{H}[✓] Port {port} terbuka - Banner: {banner if banner else 'tidak tersedia'}{RESET}")
                    s.close()

                except socket.timeout:
                    print(f"{K}[~] Port {port} timeout.{RESET}")
                except Exception as e:
                    print(f"{M}[-] Port {port} tertutup atau ditolak - {e}{RESET}")
                    continue

            if hasil_scan:
                LOGS.append({"port_scan": {
                    "ip": ip,
                    "ports_open": hasil_scan
                }})
            else:
                print(f"{K}[~] Tidak ada port terbuka yang terdeteksi.{RESET}")
                LOGS.append({"port_scan": {
                    "ip": ip,
                    "ports_open": []
                }})

        except Exception as e:
            print(f"{M}[!] siPortManja: Gagal melakukan pemindaian port - {e}{RESET}")

class siTlsSantuy:
    def jalan(self, domain):
        try:
            print(f"{B}[*] siTlsSantuy: Mengambil data TLS publik dari CertSpotter untuk {domain} ...{RESET}")
            url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
            r = requests.get(url, timeout=15)
            certs = r.json()

            parsed = []
            for cert in certs:
                entry = {
                    "issuer": cert.get("issuer", {}).get("common_name", "unknown"),
                    "dns_names": cert.get("dns_names", []),
                    "not_before": cert.get("not_before", ""),
                    "not_after": cert.get("not_after", ""),
                    "cert_url": cert.get("certificate", ""),
                    "expired": False
                }

                # Cek apakah sertifikat sudah expired
                try:
                    exp = datetime.strptime(entry["not_after"], "%Y-%m-%dT%H:%M:%SZ")
                    entry["expired"] = exp < datetime.utcnow()
                except:
                    entry["expired"] = "unknown"

                parsed.append(entry)

            LOGS.append({"tls_certspotter": parsed})

            print(f"{H}[✓] TLS ditemukan: {len(parsed)} sertifikat{RESET}")
            if parsed:
                print(f"{K}┌─ Contoh domain dari sertifikat pertama:{RESET}")
                for name in parsed[0]["dns_names"][:5]:
                    print(f"│  ↳ {name}")
                print(f"{K}└─ Diterbitkan oleh: {parsed[0]['issuer']}{RESET}")
                print(f"    🔐 Berlaku hingga: {parsed[0]['not_after']} (Expired: {parsed[0]['expired']})\n")

        except Exception as e:
            print(f"{M}[!] siTlsSantuy: Gagal mengambil data TLS - {e}{RESET}")
                
class siGithubDorking:
    def jalan(self, domain):
        try:
            print(f"{B}[*] siGithubDorking: Mencari kemungkinan kebocoran data sensitif di GitHub terkait domain: {domain}{RESET}")
            query = f'"{domain}" AND (password OR secret OR api_key OR token)'
            search_url = f"https://github.com/search?q={quote(query)}&type=Code"
            headers = HEADERS()
            headers.update({
                "Accept": "text/html,application/xhtml+xml",
                "Referer": "https://github.com/",
                "Host": "github.com"
            })

            res = requests.get(search_url, headers=headers, timeout=10)

            if res.status_code == 200 and "repository results" in res.text.lower():
                # Ekstrak beberapa judul dari hasil
                hasil_title = re.findall(r'<a class="v-align-middle" href="(.*?)">', res.text)
                hasil_title = list(set(hasil_title))[:5]  # Ambil 5 hasil unik pertama

                log_entry = {
                    "query": query,
                    "result_url": search_url,
                    "samples": [f"https://github.com{path}" for path in hasil_title]
                }
                LOGS.append({"github_dork": log_entry})

                print(f"{H}[✓] Dork GitHub berhasil dikirim dan hasil ditemukan!{RESET}")
                print(f"{K}    🔗 Link: {search_url}{RESET}")
                if hasil_title:
                    print(f"{C}    🧵 Contoh hasil pencarian GitHub:")
                    for s in log_entry["samples"]:
                        print(f"     ↳ {s}")
                else:
                    print(f"{K}    [~] Tidak ada hasil spesifik ditemukan, tetap cek manual ya.{RESET}")
            else:
                print(f"{M}[!] Permintaan GitHub gagal atau tidak ada hasil yang cocok. Status: {res.status_code}{RESET}")

        except Exception as e:
            print(f"{M}[!] siGithubDorking: Terjadi kesalahan saat request GitHub - {e}{RESET}")
                
class siEmailLeakHunter:
    def jalan(self, domain):
        try:
            print(f"{B}[*] siEmailLeakHunter: Mengecek kebocoran email umum pada domain {domain} ...{RESET}")
            kandidat_email = [f"{prefix}@{domain}" for prefix in ["admin", "support", "info", "ceo", "root"]]
            hasil_bocor = []

            for email in kandidat_email:
                url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
                headers = {
                    "User-Agent": random.choice(USER_AGENTS),
                    "hibp-api-key": "YOUR_API_KEY_HERE",  # ← ganti ini bila menggunakan HIBP resmi
                }
                try:
                    r = requests.get(url, headers=headers, timeout=10)
                    if r.status_code == 200:
                        print(f"{M}[!] Ditemukan kebocoran untuk {email}{RESET}")
                        hasil_bocor.append(email)
                    elif r.status_code == 404:
                        print(f"{H}[✓] Aman: {email} belum pernah bocor{RESET}")
                    elif r.status_code == 429:
                        print(f"{K}[!] Rate limit! Tunggu sebentar sebelum lanjut...{RESET}")
                        time.sleep(2)
                        continue
                    else:
                        print(f"{K}[!] Gagal cek {email}. Status code: {r.status_code}{RESET}")
                except Exception as err:
                    print(f"{M}[!] Error saat cek {email} → {err}{RESET}")
                    continue

            if hasil_bocor:
                LOGS.append({"leak_email": hasil_bocor})
            else:
                LOGS.append({"leak_email": "Tidak ada email bocor dari list kandidat"})

        except Exception as e:
            print(f"{M}[!] siEmailLeakHunter: Kesalahan utama saat proses recon - {e}{RESET}")
                
class siSubfinder:
    def jalan(self, domain):
        try:
            print(f"{C}[*] siSubfinder: Mengambil subdomain dari crt.sh untuk domain: {domain}{RESET}")
            r = requests.get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=10)
            hasil = json.loads(r.text)

            subs = set()
            for item in hasil:
                entry = item.get("name_value", "")
                for sub in entry.split("\n"):  # kadang hasilnya multiline
                    if domain in sub and "*" not in sub:
                        subs.add(sub.strip().lower())

            subs = list(subs)
            LOGS.append({"crtsh_subs": subs})

            if subs:
                print(f"{H}[✓] Total {len(subs)} subdomain unik ditemukan dari CRT.sh{RESET}")
                preview = subs[:10]
                for sub in preview:
                    print(f"     ➤ {sub}")
                if len(subs) > 10:
                    print(f"     ...dan {len(subs) - 10} lainnya tersembunyi")
            else:
                print(f"{K}[~] Tidak ada subdomain valid ditemukan dari CRT.sh{RESET}")

        except requests.exceptions.RequestException as req_err:
            print(f"{M}[!] siSubfinder: Error permintaan HTTP - {req_err}{RESET}")
        except json.decoder.JSONDecodeError as json_err:
            print(f"{M}[!] siSubfinder: Format JSON dari CRT.sh tidak valid - {json_err}{RESET}")
        except Exception as e:
            print(f"{M}[!] siSubfinder: Terjadi kesalahan umum - {e}{RESET}")
                
class siJsDepFinger:
    def jalan(self, domain):
        try:
            print(f"{C}[*] siJsDepFinger: Mendeteksi library JS usang di domain: {domain}{RESET}")
            js_urls = [f"https://{domain}/{w}" for w in WORDLIST if w.endswith('.js')]
            found_any = False
            lib_versions = {
                "jquery": r"jquery[-.]?([0-9.]+)",
                "angular": r"angular[-.]?([0-9.]+)",
                "bootstrap": r"bootstrap[-.]?([0-9.]+)",
                "react": r"react[-.]?([0-9.]+)"
            }
            outdated = {
                "jquery": "3.6.0",
                "angular": "11.0.0",
                "bootstrap": "4.6.0",
                "react": "17.0.0"
            }

            for js in js_urls:
                try:
                    r = requests.get(js, timeout=5)
                    content = r.text
                    for lib, regex in lib_versions.items():
                        match = re.search(regex, content, re.IGNORECASE)
                        if match:
                            version = match.group(1)
                            if version and version < outdated[lib]:
                                found_any = True
                                log_msg = f"{lib} v{version} (usang) ditemukan di {js}"
                                LOGS.append({"js_dep": log_msg})
                                print(f"{M}[!] {lib} versi usang ditemukan: v{version} di {js}{RESET}")
                except Exception as e:
                    print(f"{K}[~] Gagal cek JS: {js} - {e}{RESET}")
                    continue

            if not found_any:
                print(f"{H}[✓] Tidak ditemukan library JS usang pada domain: {domain}{RESET}")

        except Exception as e:
            print(f"{M}[!] siJsDepFinger: Error saat pengecekan - {e}{RESET}")
                
class siAsnMaper:
    def jalan(self, domain):
        try:
            print(f"{C}[*] siAsnMaper: Mengambil informasi ASN untuk domain: {domain}{RESET}")
            ip = socket.gethostbyname(domain)
            print(f"{B}[i] IP publik domain: {ip}{RESET}")
            r = requests.get(f"https://api.hackertarget.com/aslookup/?q={ip}", timeout=10)
            hasil = r.text.strip()
            if not hasil or "No ASN" in hasil or "error" in hasil.lower():
                print(f"{K}[~] Tidak ditemukan data ASN valid untuk IP {ip}{RESET}")
                LOGS.append({"asn": f"Tidak ditemukan ASN untuk {ip}"})
            else:
                print(f"{H}[✓] ASN ditemukan:\n{hasil}{RESET}")
                LOGS.append({"asn": hasil})
        except Exception as e:
            print(f"{M}[!] siAsnMaper: Gagal mengambil ASN - {e}{RESET}")
                
class siWaybackPeeker:
    def jalan(self, domain):
        try:
            print(f"{C}[*] siWaybackPeeker: Mengambil snapshot arsip dari Wayback Machine untuk: {domain}{RESET}")
            url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&collapse=urlkey"
            r = requests.get(url, timeout=10)
            hasil = r.json()

            if hasil and len(hasil) > 1:
                arsip = hasil[1:]  # skip header
                print(f"{H}[✓] {len(arsip)} arsip ditemukan di Wayback Machine untuk {domain}{RESET}")
                contoh_output = []

                for snap in arsip[:5]:
                    if len(snap) >= 3:
                        timestamp = snap[1]
                        original_url = snap[2] if snap[2].startswith("http") else f"http://web.archive.org/web/{timestamp}/{snap[2]}"
                        contoh_output.append((timestamp, original_url))
                        print(f"{B}     ➤ {timestamp} → {original_url}{RESET}")
                    else:
                        print(f"{K}[~] Snapshot tidak valid: {snap}{RESET}")

                LOGS.append({"wayback": contoh_output})
            else:
                print(f"{K}[~] Tidak ada arsip ditemukan untuk {domain} di Wayback Machine.{RESET}")
                LOGS.append({"wayback": "tidak ada data ditemukan"})
        except Exception as e:
            print(f"{M}[!] siWaybackPeeker: Gagal mengambil data dari Wayback Machine - {e}{RESET}")
                
class siJsEndpointHunter:
    def jalan(self, domain):
        try:
            print(f"{C}[*] siJsEndpointHunter: Memindai endpoint dari file JavaScript di domain: {domain}{RESET}")
            hasil_final = {}
            total_endpoint = 0
            for js in WORDLIST:
                if js.endswith(".js"):
                    url = f"https://{domain}/{js}"
                    try:
                        r = requests.get(url, timeout=5)
                        endpoints = re.findall(r"(https?://[^\s\"']+)", r.text)
                        if endpoints:
                            hasil_final[url] = list(set(endpoints))  # Hindari duplikat
                            total_endpoint += len(hasil_final[url])
                            print(f"{H}[✓] Ditemukan {len(hasil_final[url])} endpoint di {url}{RESET}")
                            for ep in hasil_final[url][:5]:  # tampilkan maksimal 5
                                print(f"{B}    ➤ {ep}{RESET}")
                    except Exception as e:
                        print(f"{M}[!] Gagal mengakses JS: {url} - {e}{RESET}")
            if hasil_final:
                LOGS.append({"js_endpoints": hasil_final})
                print(f"{H}[✓] Total endpoint ditemukan dari semua JS: {total_endpoint}{RESET}")
            else:
                print(f"{K}[~] Tidak ditemukan endpoint dari file JS apapun di {domain}{RESET}")
        except Exception as e:
            print(f"{M}[!] siJsEndpointHunter: Terjadi kesalahan umum - {e}{RESET}")
                
class siDirForce:
    def jalan(self, domain):
        try:
            print(f"{C}[*] siDirForce: Melakukan directory brute-force terhadap {domain}{RESET}")
            hasil = {"200_OK": [], "403_Forbidden": [], "3xx_Redirect": []}
            for w in WORDLIST:
                url = f"https://{domain}/{w}"
                try:
                    r = requests.get(url, timeout=3, allow_redirects=False)
                    if r.status_code == 200:
                        hasil["200_OK"].append(url)
                        print(f"{H}[✓] 200 OK ➤ {url}{RESET}")
                    elif r.status_code == 403:
                        hasil["403_Forbidden"].append(url)
                        print(f"{K}[×] 403 Forbidden ➤ {url}{RESET}")
                    elif str(r.status_code).startswith("3"):
                        hasil["3xx_Redirect"].append(url)
                        print(f"{B}[→] {r.status_code} Redirect ➤ {url}{RESET}")
                except Exception as e:
                    print(f"{M}[!] Gagal mengakses {url} - {e}{RESET}")
            if any(hasil.values()):
                LOGS.append({"dir_force": hasil})
                print(f"{H}[✓] Total direktori aktif: {len(hasil['200_OK'])}, redirect: {len(hasil['3xx_Redirect'])}, forbidden: {len(hasil['403_Forbidden'])}{RESET}")
            else:
                print(f"{K}[~] Tidak ada direktori valid ditemukan pada {domain}{RESET}")
        except Exception as e:
            print(f"{M}[!] siDirForce: Terjadi kesalahan umum - {e}{RESET}")
                
class siVHostFinder:
    def jalan(self, domain):
        try:
            print(f"{C}[*] siVHostFinder: Mendeteksi virtual host untuk domain: {domain}{RESET}")
            ip = socket.gethostbyname(domain)
            vhosts = []
            for sub in ["test", "dev", "admin", "api", "staging", "uat", "vpn", "internal"]:
                host = f"{sub}.{domain}"
                try:
                    s = socket.gethostbyname(host)
                    vhosts.append(host)
                    print(f"{H}[✓] VHost AKTIF ➤ {host} ➝ {s}{RESET}")
                except socket.gaierror:
                    print(f"{K}[×] VHost TIDAK AKTIF ➤ {host}{RESET}")
            if vhosts:
                LOGS.append({"vhost": vhosts})
                print(f"{H}[✓] Total VHost aktif ditemukan: {len(vhosts)}{RESET}")
            else:
                print(f"{K}[~] Tidak ditemukan VHost aktif untuk domain ini.{RESET}")
        except Exception as e:
            print(f"{M}[!] siVHostFinder: Gagal mendeteksi VHost - {e}{RESET}")
                
class siSpfDkim:
    def jalan(self, domain):
        try:
            print(f"{C}[*] siSpfDkim: Mengecek SPF, DKIM, dan DMARC record pada domain: {domain}{RESET}")
            hasil = {}

            try:
                spf_records = resolver.resolve(domain, "TXT")
                for r in spf_records:
                    if "v=spf1" in str(r):
                        hasil["SPF"] = str(r)
                        LOGS.append({"SPF": str(r)})
                        print(f"{H}[✓] SPF record ditemukan: {str(r)}{RESET}")
                        break
                else:
                    print(f"{K}[~] SPF record tidak ditemukan.{RESET}")
            except Exception as e:
                print(f"{M}[!] Gagal cek SPF: {e}{RESET}")

            try:
                dmarc_domain = f"_dmarc.{domain}"
                dmarc_records = resolver.resolve(dmarc_domain, "TXT")
                for r in dmarc_records:
                    if "v=DMARC1" in str(r):
                        hasil["DMARC"] = str(r)
                        LOGS.append({"DMARC": str(r)})
                        print(f"{H}[✓] DMARC record ditemukan: {str(r)}{RESET}")
                        break
                else:
                    print(f"{K}[~] DMARC record tidak ditemukan.{RESET}")
            except Exception as e:
                print(f"{M}[!] Gagal cek DMARC: {e}{RESET}")

            for selector in ["default", "google", "mail", "selector1", "selector2"]:
                try:
                    dkim_domain = f"{selector}._domainkey.{domain}"
                    dkim_records = resolver.resolve(dkim_domain, "TXT")
                    for r in dkim_records:
                        if "v=DKIM1" in str(r):
                            hasil["DKIM"] = f"{selector}: {str(r)}"
                            LOGS.append({f"DKIM ({selector})": str(r)})
                            print(f"{H}[✓] DKIM record ditemukan ({selector}): {str(r)}{RESET}")
                            break
                except:
                    continue

            if not hasil:
                print(f"{K}[~] Tidak ditemukan SPF, DKIM, maupun DMARC pada domain ini.{RESET}")

        except Exception as e:
            print(f"{M}[!] siSpfDkim: Gagal mendapatkan record DNS - {e}{RESET}")
                
class siTechyFinder:
    def jalan(self, domain):
        try:
            print(f"{C}[*] siTechyFinder: Mendeteksi teknologi yang digunakan oleh {domain}{RESET}")
            r = requests.get(f"https://{domain}", headers=HEADERS(), timeout=8)
            tech = []

            if "wp-content" in r.text or "wp-json" in r.text:
                tech.append("WordPress")
                print(f"{H}[✓] Teknologi terdeteksi: WordPress{RESET}")
            
            if "cdn.shopify.com" in r.text or "Shopify.theme" in r.text:
                tech.append("Shopify")
                print(f"{H}[✓] Teknologi terdeteksi: Shopify{RESET}")

            if "laravel_session" in str(r.headers).lower():
                tech.append("Laravel")
                print(f"{H}[✓] Teknologi terdeteksi: Laravel (via Cookie){RESET}")
            
            if "cloudflare" in str(r.headers).lower():
                tech.append("Cloudflare")
                print(f"{H}[✓] Ditemukan proteksi: Cloudflare{RESET}")
            
            if "react" in r.text.lower():
                tech.append("React.js")
                print(f"{H}[✓] Framework terdeteksi: React.js{RESET}")
            
            if "vue" in r.text.lower():
                tech.append("Vue.js")
                print(f"{H}[✓] Framework terdeteksi: Vue.js{RESET}")

            if "bootstrap.min.css" in r.text:
                tech.append("Bootstrap")
                print(f"{H}[✓] CSS Framework: Bootstrap{RESET}")
            
            if "fontawesome" in r.text.lower():
                tech.append("FontAwesome")
                print(f"{H}[✓] Icon library: FontAwesome{RESET}")

            if "www.google-analytics.com/analytics.js" in r.text:
                tech.append("Google Analytics")
                print(f"{H}[✓] Tracker: Google Analytics{RESET}")

            if not tech:
                print(f"{K}[~] Tidak ada teknologi umum yang terdeteksi di halaman utama.{RESET}")
            else:
                LOGS.append({"tech_detected": tech})

        except Exception as e:
            print(f"{M}[!] siTechyFinder: Gagal mendeteksi teknologi - {e}{RESET}")
                
class siS3Hunter:
    def jalan(self, domain):
        try:
            print(f"{C}[*] siS3Hunter: Mengecek apakah bucket S3 {domain}.s3.amazonaws.com dapat diakses publik...{RESET}")
            s3_url = f"http://{domain}.s3.amazonaws.com"
            r = requests.get(s3_url, timeout=8)

            if "ListBucketResult" in r.text:
                LOGS.append({"s3_bucket": "Public"})
                print(f"{H}[✓] Bucket S3 TERBUKA untuk publik: {s3_url}{RESET}")
            elif "AccessDenied" in r.text:
                print(f"{K}[~] Bucket ditemukan, tapi AKSES DITOLAK: {s3_url}{RESET}")
                LOGS.append({"s3_bucket": "Exist but Denied"})
            elif "NoSuchBucket" in r.text or r.status_code == 404:
                print(f"{M}[x] Bucket tidak ditemukan: {s3_url}{RESET}")
                LOGS.append({"s3_bucket": "Not Found"})
            else:
                print(f"{K}[~] Respon ambigu, perlu pengecekan manual: {s3_url}{RESET}")
                LOGS.append({"s3_bucket": "Unknown or Indirect Response"})

        except Exception as e:
            print(f"{M}[!] siS3Hunter: Gagal melakukan pengecekan bucket S3 - {e}{RESET}")
                
class siPastebinNinja:
    def jalan(self, domain):
        try:
            print(f"{C}[*] siPastebinNinja: Melakukan pencarian intelijen terbuka di Pastebin untuk domain: {domain}{RESET}")
            
            search_url = f"https://pastebin.com/search?q={domain}"
            headers = HEADERS()
            r = requests.get(search_url, headers=headers, timeout=8)

            if r.status_code == 200:
                paste_ids = re.findall(r"/[a-zA-Z0-9]{8}", r.text)
                paste_ids = list(set(paste_ids))[:5]  # Ambil 5 paste ID teratas
                full_links = [f"https://pastebin.com{id}" for id in paste_ids]

                if paste_ids:
                    print(f"{H}[✓] Ditemukan kemungkinan bocoran publik di Pastebin terkait domain ini:")
                    for link in full_links:
                        print(f"    ➤ {link}")
                    LOGS.append({"pastebin_links": full_links})
                else:
                    print(f"{K}[~] Tidak ada hasil yang terdeteksi secara langsung dari hasil HTML. Tetap cek manual: {search_url}")
                    LOGS.append({"pastebin": "Manual review required", "url": search_url})
            else:
                print(f"{M}[x] Gagal melakukan pencarian ke Pastebin. Status: {r.status_code}")
                LOGS.append({"pastebin_error": r.status_code})
        except Exception as e:
            print(f"{M}[!] siPastebinNinja: Gagal melakukan pencarian Pastebin - {e}{RESET}")
                
class siSocmedSpy:
    def jalan(self, domain):
        try:
            email = f"admin@{domain}"
            print(f"{C}[*] siSocmedSpy: Melacak jejak sosial untuk {email} melalui LinkedIn, Hunter, dan pencarian manual...{RESET}")
            
            linkedin_url = f"https://www.linkedin.com/search/results/all/?keywords={email}"
            hunter_url = f"https://hunter.io/search/{domain}"

            urls = {
                "LinkedIn Search": linkedin_url,
                "Hunter.io Lookup": hunter_url,
                "Google Dork": f"https://www.google.com/search?q={email}+site:twitter.com+OR+site:linkedin.com+OR+site:facebook.com"
            }

            for label, link in urls.items():
                print(f"{H}[+] {label}: {link}")

            LOGS.append({
                "socmed_recon": {
                    "email_tracked": email,
                    "linkedin": linkedin_url,
                    "hunter": hunter_url,
                    "google_dork": urls["Google Dork"]
                }
            })

        except Exception as e:
            print(f"{M}[!] siSocmedSpy: Gagal melakukan pencarian sosial media - {e}{RESET}")
                
class siBingDorker:
    def jalan(self, domain):
        try:
            print(f"{C}[*] siBingDorker: Melakukan Bing Dorking untuk mencari file sensitif di domain {domain}{RESET}")
            queries = [
                f"site:{domain} filetype:env",
                f"site:{domain} filetype:log",
                f"site:{domain} ext:bak | ext:old | ext:backup",
                f"site:{domain} intitle:index.of",
                f"site:{domain} inurl:admin",
                f"site:{domain} filetype:sql",
                f"site:{domain} filetype:json"
            ]
            hasil = []

            for q in queries:
                print(f"{H}  [+] Query: {q}{RESET}")
                url = f"https://www.bing.com/search?q={q}"
                try:
                    r = requests.get(url, headers=HEADERS(), timeout=8)
                    found = re.findall(r"https?://[^\s\"'<>]+", r.text)
                    hasil.extend(found)
                    print(f"{C}    [-] {len(found)} URL ditemukan untuk query ini{RESET}")
                except Exception as req_err:
                    print(f"{M}    [!] Gagal request Bing untuk query: {q} - {req_err}{RESET}")
                    continue

            hasil_unik = sorted(set(hasil))
            if hasil_unik:
                LOGS.append({"bing_dork": hasil_unik})
                print(f"{H}[✓] Total unik hasil dorking Bing: {len(hasil_unik)}{RESET}")
                for link in hasil_unik[:5]:
                    print(f"{B}     ➤ {link}{RESET}")
                if len(hasil_unik) > 5:
                    print(f"{K}     ➤ ...dan {len(hasil_unik) - 5} hasil lainnya{RESET}")
            else:
                print(f"{K}[~] Tidak ada hasil unik ditemukan dalam pencarian Bing.{RESET}")

        except Exception as e:
            print(f"{M}[!] siBingDorker: Gagal total saat dorking Bing - {e}{RESET}")
                
class siLoginPageSniper:
    def jalan(self, domain):
        try:
            print(f"{C}[*] siLoginPageSniper: Mencari halaman login pada domain {domain}{RESET}")
            logins = []
            hints = [
                "admin", "login", "signin", "dashboard", "cpanel", "account", "user", "auth",
                "secure", "access", "panel", "system", "member", "staff"
            ]
            for hint in hints:
                url = f"https://{domain}/{hint}"
                try:
                    r = requests.get(url, timeout=5, headers=HEADERS())
                    if r.status_code == 200:
                        if any(keyword in r.text.lower() for keyword in ["password", "username", "login", "signin", "auth"]):
                            logins.append(url)
                            print(f"{H}[✓] Halaman login terdeteksi: {url}{RESET}")
                        else:
                            print(f"{K}[~] {url} aktif, tapi tidak ada form login terdeteksi.{RESET}")
                    elif r.status_code in [301, 302]:
                        redirect_to = r.headers.get("Location", "")
                        print(f"{B}[→] {url} redirect ke {redirect_to}{RESET}")
                except Exception as e:
                    print(f"{M}[!] Gagal akses {url} - {e}{RESET}")
            if not logins:
                print(f"{K}[~] Tidak ditemukan halaman login dari path umum atau ciri otentikasi tidak terdeteksi.{RESET}")
            LOGS.append({"login_pages": logins})
        except Exception as e:
            print(f"{M}[!] siLoginPageSniper: Gagal proses pencarian halaman login - {e}{RESET}")

class siOpenRedirectHunter:
    def jalan(self, domain):
        try:
            print(f"{C}[*] siOpenRedirectHunter: Mencoba mendeteksi kerentanan Open Redirect pada domain {domain}{RESET}")
            param = ["redirect", "next", "url", "return", "dest", "destination", "continue"]
            hasil = []
            payload = "https://pornhub.com"

            for p in param:
                test_url = f"https://{domain}/?{p}={payload}"
                try:
                    r = requests.get(test_url, allow_redirects=False, timeout=5, headers=HEADERS())
                    location = r.headers.get("Location", "")
                    if payload in location:
                        hasil.append(test_url)
                        print(f"{H}[✓] Potensi Open Redirect ditemukan pada: {test_url}{RESET}")
                    elif r.status_code in [300, 301, 302, 303, 307, 308]:
                        print(f"{K}[~] {test_url} melakukan redirect ke: {location}, tapi bukan payload.{RESET}")
                    else:
                        print(f"{K}[~] Tidak ada redirect di {test_url} (status {r.status_code}){RESET}")
                except Exception as e:
                    print(f"{M}[!] Gagal mengakses {test_url} - {e}{RESET}")

            if not hasil:
                print(f"{B}[i] Tidak ditemukan kerentanan Open Redirect yang eksplisit.{RESET}")
            LOGS.append({"open_redirect": hasil})
        except Exception as e:
            print(f"{M}[!] siOpenRedirectHunter: Error utama - {e}{RESET}")
                
class siFaviconHashHunter:
    def jalan(self, domain):
        try:
            print(f"{C}[*] siFaviconHashHunter: Mengambil favicon & menghitung hash untuk {domain}{RESET}")
            r = requests.get(f"https://{domain}/favicon.ico", timeout=5, headers=HEADERS())
            if r.status_code != 200 or not r.content:
                print(f"{M}[!] Gagal mengambil favicon dari {domain}{RESET}")
                return

            import hashlib
            content = r.content

            md5_hash = hashlib.md5(content).hexdigest()
            sha1_hash = hashlib.sha1(content).hexdigest()
            sha256_hash = hashlib.sha256(content).hexdigest()

            LOGS.append({
                "favicon_hash": {
                    "md5": md5_hash,
                    "sha1": sha1_hash,
                    "sha256": sha256_hash
                }
            })

            print(f"{H}[✓] Hash Favicon Dihitung untuk {domain}:{RESET}")
            print(f"    ➤ MD5   : {md5_hash}")
            print(f"    ➤ SHA1  : {sha1_hash}")
            print(f"    ➤ SHA256: {sha256_hash}")

            fingerprint_dict = {
                "d41d8cd98f00b204e9800998ecf8427e": "Empty Favicon / Blank",
                "3a0fa0f7c48efedb4a9ad2dba3fa5b17": "Apache Default Page",
                "5d3f5f7bd8033cb7ad5603d97c0f4696": "CPanel Login",
                "e6e69bb58f6f78cbe9b294b0c71cde2e": "WordPress Admin",
            }

            if md5_hash in fingerprint_dict:
                print(f"{K}[~] Favicon cocok dengan fingerprint: {fingerprint_dict[md5_hash]}{RESET}")
                LOGS.append({"favicon_fingerprint": fingerprint_dict[md5_hash]})
            else:
                print(f"{B}[i] Tidak ada fingerprint cocok dalam basis data lokal.{RESET}")

        except Exception as e:
            print(f"{M}[!] siFaviconHashHunter: Gagal menghitung hash favicon - {e}{RESET}")
                
class siEmailPatternCrafter:
    def jalan(self, domain):
        try:
            import smtplib
            import dns.resolver

            print(f"{C}[*] siEmailPatternCrafter: Memulai pembuatan & verifikasi pola email di domain: {domain}{RESET}")
            pola = ["admin", "ceo", "info", "sales", "support", "hrd", "marketing"]
            hasil = []
            try:
                mx_records = dns.resolver.resolve(domain, 'MX')
                mx_host = str(sorted(mx_records, key=lambda r: r.preference)[0].exchange).rstrip('.')
                print(f"{H}[✓] MX Record ditemukan: {mx_host}{RESET}")
            except Exception as e:
                print(f"{M}[!] Tidak bisa resolve MX record - fallback ke smtp.{domain}{RESET}")
                mx_host = f"smtp.{domain}"

            for p in pola:
                email = f"{p}@{domain}"
                try:
                    server = smtplib.SMTP(mx_host, 25, timeout=7)
                    server.helo()
                    server.mail("test@pentest.local")

                    code, msg = server.rcpt(email)
                    if code == 250 or code == 251:
                        hasil.append(email)
                        print(f"{H}[✓] Email aktif ditemukan: {email} ({code}){RESET}")
                    else:
                        print(f"{K}[~] Ditolak: {email} ({code}){RESET}")
                    server.quit()
                except Exception as e:
                    print(f"{M}[!] Gagal verifikasi {email} - {e}{RESET}")

            if not hasil:
                print(f"{K}[~] Tidak ditemukan email aktif dari pola yang diuji.{RESET}")
            LOGS.append({
                "emails_found": hasil,
                "mx_host": mx_host
            })

        except Exception as e:
            print(f"{M}[!] siEmailPatternCrafter: Gagal menjalankan modul - {e}{RESET}")
                
class siGraphBuilder:
    def jalan(self, domain):
        try:
            print(f"{C}[*] siGraphBuilder: Membangun struktur graph dari hasil modul untuk domain: {domain}{RESET}")
            edges = []
            nodes = set()
            jenis_hasil = {}

            for log in LOGS:
                for k, v in log.items():
                    edges.append((domain, k))
                    nodes.update([domain, k])
                    jenis_hasil[k] = jenis_hasil.get(k, 0) + 1

            graph_summary = {
                "nodes": list(nodes),
                "edges": edges,
                "node_count": len(nodes),
                "edge_count": len(edges),
                "statistik": jenis_hasil
            }

            LOGS.append({"graph_edges": graph_summary})

            print(f"{H}[✓] Total Node unik: {len(nodes)}{RESET}")
            print(f"{H}[✓] Total Edge (relasi): {len(edges)}{RESET}")
            print(f"{B}[i] Statistik hubungan per modul yang ditemukan:{RESET}")
            for jenis, count in jenis_hasil.items():
                print(f"    ➤ {jenis}: {count} hasil")

        except Exception as e:
            print(f"{M}[!] siGraphBuilder: Gagal membangun graph - {e}{RESET}")
                
class siAutoExploitStarter:
    def jalan(self, domain):
        try:
            print(f"{C}[*] siAutoExploitStarter: Memulai otomatisasi XSS testing adaptif untuk domain {domain}{RESET}")
            payloads = [
                "<script>alert(1)</script>",
                "\"><script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>"
            ]
            params = ["q", "search", "input", "s"]
            found_total = 0
            tested_urls = []

            for log in LOGS:
                if "dir" in log:
                    for base_url in log["dir"]:
                        for param in params:
                            for payload in payloads:
                                try:
                                    test_url = f"{base_url}?{param}={payload}"
                                    tested_urls.append(test_url)
                                    r = requests.get(test_url, timeout=6)
                                    if payload in r.text:
                                        hasil = f"XSS ditemukan di {test_url}"
                                        LOGS.append({"xss_auto": hasil})
                                        print(f"{H}[✓] {hasil}{RESET}")
                                        found_total += 1
                                except Exception as e:
                                    print(f"{M}[!] Gagal eksploitasi ke {test_url} - {e}{RESET}")
            if found_total == 0:
                print(f"{K}[!] Tidak ditemukan XSS yang terefleksi.{RESET}")
            else:
                print(f"{B}[✓] Total {found_total} eksploitasi XSS berhasil{RESET}")
            LOGS.append({"xss_tested": tested_urls})
        except Exception as e:
            print(f"{M}[!] siAutoExploitStarter error: {e}{RESET}")

async def main(domain):
    modul = [
        siWhoisPasif(), siShodanKasian(), siDNSZoneBomb(), siSubdomainHunter(), siCorsKocak(),
        siWafDetektor(), siCDNHeadHunter(), siCmsNinja(), siPortManja(), siTlsSantuy(),
        siGithubDorking(), siEmailLeakHunter(), siSubfinder(), siJsDepFinger(),
        siAsnMaper(), siWaybackPeeker(), siJsEndpointHunter(), siDirForce(), siVHostFinder(),
        siSpfDkim(), siTechyFinder(), siS3Hunter(), siPastebinNinja(), siSocmedSpy(),
        siBingDorker(), siLoginPageSniper(), siOpenRedirectHunter(), siFaviconHashHunter(),
        siEmailPatternCrafter(), siGraphBuilder(), siAutoExploitStarter()
    ]

    threads = []  

    for m in modul:
        t = threading.Thread(target=m.jalan, args=(domain,))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    json_path = f"laporan_{domain}.json"
    txt_path = f"laporan_{domain}.txt"

    with open(json_path, "w") as f:
        json.dump(LOGS if LOGS else [{"info": "Tidak ada hasil ditemukan"}], f, indent=4)

    with open(txt_path, "w") as f:
        for l in LOGS if LOGS else [{"info": "Tidak ada hasil ditemukan"}]:
            f.write(json.dumps(l) + "\n")

    print(f"[✓] Laporan berhasil disimpan: {json_path} dan {txt_path}")


if __name__ == "__main__":
    target = input("Masukin domain target: ").strip()
    target = target.replace("https://", "").replace("http://", "").strip("/")
    asyncio.run(main(target))
