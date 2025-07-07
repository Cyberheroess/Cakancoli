
import requests, socket, re, json, asyncio, aiohttp, threading, subprocess, os, random, time
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from dns import resolver, exception
from datetime import datetime

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
            print(f"[*] siWhoisPasif: Mengambil data WHOIS dari {domain} ...")
            whois_url = f"https://www.whois.com/whois/{domain}"
            res = requests.get(whois_url, headers=HEADERS(), proxies=PROXY(), timeout=10)
            hasil = re.findall(r"Registry Expiry Date:.*", res.text)
            LOGS.append({"whois": hasil})
            if hasil:
                print(f"[+] siWhoisPasif: Registry Expiryy Datn ditemukan: {hasil}")
            else:
                print("[~] siWhoisPasif: Tidak ditemukan tunggal kadaluarsa dalam WHOIS.")
        except Exception as e:
            print(f"[!] siWhoisPasif: Gagal mengambil WHOIS - {e}")

class siShodanKasian:
    def jalan(self, domain):
        try:
            print(f"[*] siShodanKasian: Mencari informasi dari Shodan untuk {domain} ...")
            ip = socket.gethostbyname(domain)
            print(f"[+] siShodanKasian: IP address domain: {ip}")
            url = f"https://api.shodan.io/shodan/host/{ip}?key=SHODAN_API_KEY"
            res = requests.get(url, timeout=10)
            hasil = res.json()
            LOGS.append({"shodan": hasil})
            if "error" not in hasil:
                print(f"[+] siShodanKasian: Data Shodan berhasil diambil untuk IP {ip}")
            else:
                print(f"[~] siShodanKasian: Shodan mengembalikan error: {hasil['error']}")
        except Exception as e:
            print(f"[!] siShodanKasian: Gagal mengakses Shodan - {e}")

class siDNSZoneBomb:
    def jalan(self, domain):
        try:
            print(f"[*] siDNSZoneBomb: Memulai pencarian DNS Zone Transfer untuk {domain} ...")
            nameservers = resolver.resolve(domain, 'NS')
            for ns in nameservers:
                try:
                    print(f"    [+] Mencoba AXFR ke NS: {ns.target}")
                    axfr = resolver.zone_for_name(domain, nameserver=str(ns.target))
                    LOGS.append({"zone_transfer": f"Berhasil di {ns.target}"})
                    print(f"[✓] siDNSZoneBomb: Zone Transfer BERHASIL di NS: {ns.target}")
                    break
                except Exception as e:
                    print(f"    [-] AXFR gagal di NS {ns.target} - {e}")
                    continue
        except Exception as e:
            print(f"[!] siDNSZoneBomb: Gagal resolve NS untuk {domain} - {e}")

class siSubdomainHunter:
    def jalan(self, domain):
        try:
            print(f"[*] siSubdomainHunter: Memulai enumerasi subdomain melalui file .js di {domain} ...")
            subs = set()
            js_files = [f"https://{domain}/{w}" for w in WORDLIST if w.endswith('.js')]
            for js in js_files:
                try:
                    print(f"    [+] Mengambil file JS: {js}")
                    r = requests.get(js, headers=HEADERS(), timeout=5)
                    found = re.findall(r"(?:https?://)?([\w\-]+\." + domain.replace(".", r"\.") + ")", r.text)
                    if found:
                        print(f"        [✓] Ditemukan subdomain: {found}")
                    subs.update(found)
                except Exception as e:
                    print(f"    [-] Gagal fetch {js} - {e}")
                    continue
            if subs:
                LOGS.append({"subdomains": list(subs)})
                print(f"[+] siSubdomainHunter: Total subdomain ditemukan: {len(subs)}")
            else:
                print(f"[~] siSubdomainHunter: Tidak ada subdomain ditemukan.")
        except Exception as e:
            print(f"[!] siSubdomainHunter: Terjadi kesalahan - {e}")

class siCorsKocak:
    def jalan(self, domain):
        try:
            print(f"[*] siCorsKocak: Mengecek CORS misconfiguration di https://{domain} ...")
            r = requests.options(f"https://{domain}", headers={"Origin": "https://evil.com"})
            expose = r.headers.get("Access-Control-Allow-Origin")
            if expose == "*":
                print(f"[✓] CORS mnisconfiguration terdeteksi: Allow-Origin adalah '*'")
                LOGS.append({"cors": "Misconfig Detected"})
            elif "evil.com" in str(expose).lower():
                print(f"[✓] CORS misconfiguration terdeteksi: Origin evil.com diterima!")
                LOGS.append({"cors": "Misconfig Detected"})
            else:
                print(f"[~] Tidak ada CORS misconfiguration ditemukan.")
        except Exception as e:
            print(f"[!] siCorsKocak: Gagal memeriksa CORS - {e}")

class siWafDetektor:
    def jalan(self, domain):
        try:
            print(f"[*] siWafDetektor: Mndeteksi WAF aktif di https://{domain} ...")
            url = f"https://{domain}"
            r = requests.get(url, headers=HEADERS(), timeout=10)
            waf_sign = ["cloudflare", "sucuri", "akamai", "f5"]
            ditemukan = False
            for w in waf_sign:
                if w in r.text.lower() or w in str(r.headers).lower():
                    LOGS.append({"waf": f"Ditemukan WAF: {w}"})
                    print(f"[✓] WAF terdeteksi: {w}")
                    ditemukan = True
                    break
            if not ditemukan:
                print(f"[~] Tidak ada WAF umum terdeteksi pada konten atau header.")
        except Exception as e:
            print(f"[!] siWafDetektor: Error saat memeriksa WAF - {e}")

class siCDNHeadHunter:
    def jalan(self, domain):
        try:
            print(f"[*] siCDNHeadHunter: Menganalisis kemungkinan penggunaan CDN oleh {domain} ...")
            ip = socket.gethostbyname(domain)
            ttl = subprocess.check_output(["ping", "-c", "1", domain]).decode()
            headers = requests.get(f"https://{domain}", headers=HEADERS(), timeout=5).headers
            cdn_sign = any("cloudflare" in h.lower() for h in headers)
            LOGS.append({"cdn": {"ip": ip, "ttl": ttl, "header_cdn": cdn_sign}})
            print(f"[✓] IP: {ip}")
            print(f"[✓] TTL Ping:\n{ttl.strip()}")
            print(f"[✓] Header mengandung CDN (Cloudflare): {cdn_sign}")
        except Exception as e:
            print(f"[!] siCDNHeadHunter: Error mendeteksi CDN - {e}")

class siCmsNinja:
    def jalan(self, domain):
        try:
            print(f"[*] siCmsNinja: Mendeteksi CMS yang digunakan oleh {domain} ...")
            r = requests.get(f"https://{domain}", headers=HEADERS(), timeout=8)
            if "/wp-content/" in r.text:
                LOGS.append({"cms": "WordPress"})
                print(f"[✓] CMS Terdeteksi: WordPress")
            elif "Joomla" in r.text:
                LOGS.append({"cms": "Joomla"})
                print(f"[✓] CMS Terdeteksi: Joomla")
            elif "Drupal.settings" in r.text:
                LOGS.append({"cms": "Drupal"})
                print(f"[✓] CMS Terdeteksi: Drupal")
            else:
                print(f"[~] CMS tidak dapat dikenali dari konten halaman.")
        except Exception as e:
            print(f"[!] siCmsNinja: Error saat mendeteksi CMS - {e}")

class siPortManja:
    def jalan(self, domain):
        try:
            ip = socket.gethostbyname(domain)
            for port in [80, 443, 8080, 8443]:
                try:
                    s = socket.socket()
                    s.settimeout(2)
                    s.connect((ip, port))
                    LOGS.append({"port_open": port})
                    s.close()
                except: continue
        except: pass

class siPortManja:
    def jalan(self, domain):
        try:
            print(f"[*] siPortManja: Memindai port umum pada {domain} ...")
            ip = socket.gethostbyname(domain)
            print(f"[✓] Alamat IP: {ip}")
            for port in [80, 443, 8080, 8443]:
                try:
                    s = socket.socket()
                    s.settimeout(2)
                    s.connect((ip, port))
                    LOGS.append({"port_open": port})
                    print(f"[+] Port terbuka terdeteksi: {port}")
                    s.close()
                except:
                    print(f"[-] Port {port} tertutup atau tidak merespons.")
                    continue
        except Exception as e:
            print(f"[!] siPortManja: Gagal memindai port - {e}")

class siTlsSantuy:
    def jalan(self, domain):
        try:
            print(f"[*] siTlsSantuy: Mengambil data sertifikat TLS publik dari CertSpotter untuk {domain} ...")
            url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
            r = requests.get(url, timeout=10)
            certs = r.json()
            LOGS.append({"tls_certspotter": certs})
            print(f"[✓] Total sertifikat ditemukan: {len(certs)}")
            if len(certs) > 0:
                print(f"[i] Contoh sertifikat pertama:")
                print(json.dumps(certs[0], indent=2)[:500] + "...\n")  # Biar nggak kepanjangan
        except Exception as e:
            print(f"[!] siTlsSantuy: Gagal mengambil data TLS - {e}")

class siGithubDorking:
    def jalan(self, domain):
        try:
            print(f"[*] siGithubDorking: Mencari kemungkinan kebocoran sensitive data di GitHub untuk domain: {domain}")
            query = f'"{domain}" AND (password OR secret)'
            search_url = f"https://github.com/search?q={quote(query)}"
            r = requests.get(search_url, headers=HEADERS())
            if r.status_code == 200:
                LOGS.append({"github_dork": "Cek hasil manual: github.com/search..."})
                print(f"[✓] Dork GitHub berhasil dikirim. Silakan periksa manual:\n    {search_url}")
            else:
                print(f"[!] Permintaan ke GitHub gagal dengan kode status: {r.status_code}")
        except Exception as e:
            print(f"[!] siGithubDorking: Terjadi error saat mengakses GitHub - {e}")

class siEmailLeakHunter:
    def jalan(self, domain):
        try:
            email = f"admin@{domain}"
            print(f"[*] siEmailLeakHunter: Mengecek apakah email '{email}' pernah bocor ...")
            r = requests.get(f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}")
            if r.status_code == 200:
                LOGS.append({"leak_email": f"Data bocor ditemukan untuk {email}"})
                print(f"[!] Ditemukan kebocoran untuk email: {email}")
            elif r.status_code == 404:
                print(f"[✓] Tidak ditemukan kebocoran untuk email: {email}")
            else:
                print(f"[!] Gagal cek kebocoran email. Status code: {r.status_code}")
        except Exception as e:
            print(f"[!] siEmailLeakHunter: Error saat akses HaveIBeenPwned - {e}")

class siSubfinder:
    def jalan(self, domain):
        try:
            print(f"[*] siSubfinder: Mengambil subdomain dari CRT.sh untuk domain: {domain}")
            r = requests.get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=10)
            hasil = json.loads(r.text)
            subs = list(set([x['name_value'] for x in hasil]))
            LOGS.append({"crtsh_subs": subs})
            print(f"[✓] Ditemukan {len(subs)} subdomain dari CRT.sh")
            if len(subs) <= 10:
                print("     ➤", "\n     ➤ ".join(subs))
            else:
                print(f"     ➤ Contoh: {subs[0]}, {subs[1]}, ...")
        except Exception as e:
            print(f"[!] siSubfinder: Gagal mengambil data dari crt.sh - {e}")

class siJsDepFinger:
    def jalan(self, domain):
        try:
            print(f"[*] siJsDepFinger: Mendeteksi library JS usang di domain: {domain}")
            js_urls = [f"https://{domain}/{w}" for w in WORDLIST if w.endswith('.js')]
            found_any = False
            for js in js_urls:
                try:
                    r = requests.get(js, timeout=5)
                    if "jquery" in r.text and "1.4" in r.text:
                        LOGS.append({"js_dep": f"Outdated lib di {js}"})
                        print(f"[!] Library usang ditemukan: jQuery 1.4 di {js}")
                        found_any = True
                except Exception as e:
                    print(f"[!] Gagal cek JS: {js} - {e}")
                    continue
            if not found_any:
                print(f"[✓] Tidak ditemukan library JS usang pada domain: {domain}")
        except Exception as e:
            print(f"[!] siJsDepFinger: Error saat pengecekan - {e}")

class siAsnMaper:
    def jalan(self, domain):
        try:
            print(f"[*] siAsnMaper: Mengambil informasi ASN untuk domain: {domain}")
            ip = socket.gethostbyname(domain)
            r = requests.get(f"https://api.hackertarget.com/aslookup/?q={ip}")
            LOGS.append({"asn": r.text})
            print(f"[✓] ASN untuk IP {ip} ditemukan:\n{r.text.strip()}")
        except Exception as e:
            print(f"[!] siAsnMaper: Gagal mengambil ASN - {e}")

class siWaybackPeeker:
    def jalan(self, domain):
        try:
            print(f"[*] siWaybackPeeker: Mengambil snapshot arsip dari Wayback Machine untuk: {domain}")
            r = requests.get(f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json")
            hasil = r.json()
            LOGS.append({"wayback": hasil[:10]})
            if hasil and len(hasil) > 1:
                print(f"[✓] {len(hasil)-1} arsip ditemukan untuk domain {domain}")
                for snap in hasil[1:6]:  # tampilkan 5 contoh pertama
                    print(f"     ➤ {snap}")
            else:
                print(f"[✓] Tidak ada arsip signifikan ditemukan untuk {domain}")
        except Exception as e:
            print(f"[!] siWaybackPeeker: Gagal mengambil data dari Wayback Machine - {e}")

class siJsEndpointHunter:
    def jalan(self, domain):
        try:
            print(f"[*] siJsEndpointHunter: Memindai endpoint dalam file JavaScript dari domain: {domain}")
            for js in WORDLIST:
                if js.endswith(".js"):
                    url = f"https://{domain}/{js}"
                    try:
                        r = requests.get(url, timeout=5)
                        find = re.findall(r"(https?://[^\s\"']+)", r.text)
                        if find:
                            LOGS.append({"js_endpoints": find})
                            print(f"[✓] Ditemukan endpoint pada {url}:")
                            for ep in find[:5]:  # tampilkan maksimal 5
                                print(f"    ➤ {ep}")
                    except Exception as e:
                        print(f"[!] Gagal mengakses JS: {url} - {e}")
        except Exception as e:
            print(f"[!] siJsEndpointHunter: Terjadi kesalahan - {e}")

class siDirForce:
    def jalan(self, domain):
        try:
            print(f"[*] siDirForce: Melakukan directory brute-force pada {domain}")
            for w in WORDLIST:
                url = f"https://{domain}/{w}"
                try:
                    r = requests.get(url, timeout=3)
                    if r.status_code == 200:
                        LOGS.append({"dir": url})
                        print(f"[✓] Direktori aktif ditemukan: {url}")
                except Exception as e:
                    print(f"[!] Error saat mencoba {url} - {e}")
        except Exception as e:
            print(f"[!] siDirForce: Terjadi kesalahan umum - {e}")

class siVHostFinder:
    def jalan(self, domain):
        try:
            print(f"[*] siVHostFinder: Mendeteksi virtual host untuk domain: {domain}")
            ip = socket.gethostbyname(domain)
            for host in ["test", "dev", "admin", "api"]:
                h = f"{host}.{domain}"
                try:
                    s = socket.gethostbyname(h)
                    LOGS.append({"vhost": h})
                    print(f"[✓] VHost ditemukan dan aktif: {h}")
                except socket.gaierror:
                    print(f"[!] VHost tidak aktif: {h}")
                    continue
        except Exception as e:
            print(f"[!] siVHostFinder: Gagal mendeteksi VHost - {e}")

class siSpfDkim:
    def jalan(self, domain):
        try:
            print(f"[*] siSpfDkim: Mengecek SPF record pada domain: {domain}")
            spf = resolver.resolve(f"{domain}", "TXT")
            for r in spf:
                if "v=spf1" in str(r):
                    LOGS.append({"spf": str(r)})
                    print(f"[✓] SPF record ditemukan: {str(r)}")
        except Exception as e:
            print(f"[!] siSpfDkim: Gagal mendapatkan SPF record - {e}")

class siTechyFinder:
    def jalan(self, domain):
        try:
            print(f"[*] siTechyFinder: Mendeteksi teknologi yang digunakan oleh {domain}")
            r = requests.get(f"https://{domain}", headers=HEADERS())
            tech = []
            if "wp-content" in r.text: 
                tech.append("WordPress")
                print(f"[✓] Teknologi terdeteksi: WordPress")
            if "cdn.shopify.com" in r.text: 
                tech.append("Shopify")
                print(f"[✓] Teknologi terdeteksi: Shopify")
            if not tech:
                print(f"[!] Tidak ditemukan tanda teknologi umum (WordPress/Shopify)")
            LOGS.append({"tech_detected": tech})
        except Exception as e:
            print(f"[!] siTechyFinder: Gagal mendeteksi teknologi - {e}")

class siS3Hunter:
    def jalan(self, domain):
        try:
            print(f"[*] siS3Hunter: Mengecek apakah bucket S3 {domain}.s3.amazonaws.com dapat diakses publik")
            s3 = f"http://{domain}.s3.amazonaws.com"
            r = requests.get(s3)
            if "ListBucketResult" in r.text:
                LOGS.append({"s3_bucket": "Public"})
                print(f"[✓] Bucket S3 terbuka untuk publik!")
            else:
                print(f"[!] Bucket S3 tidak terlihat publik atau tidak ada")
        except Exception as e:
            print(f"[!] siS3Hunter: Gagal melakukan pengecekan bucket S3 - {e}")

class siPastebinNinja:
    def jalan(self, domain):
        try:
            print(f"[*] siPastebinNinja: Melakukan pencarian cepat di Pastebin untuk domain: {domain}")
            r = requests.get(f"https://pastebin.com/search?q={domain}")
            LOGS.append({"pastebin": "Cek manual hasil pastebin"})
            print(f"[✓] Cek manual: https://pastebin.com/search?q={domain}")
        except Exception as e:
            print(f"[!] siPastebinNinja: Gagal melakukan pencarian Pastebin - {e}")

class siSocmedSpy:
    def jalan(self, domain):
        try:
            print(f"[*] siSocmedSpy: Mendeteksi kemungkinan jejak akun sosial dari email admin@{domain}")
            email = f"admin@{domain}"
            url = f"https://www.linkedin.com/search/results/all/?keywords={email}"
            LOGS.append({"socmed_recon": f"LinkedIn profile possible at: {url}"})
            print(f"[✓] Kemungkinan ditemukan LinkedIn untuk: {email}")
        except Exception as e:
            print(f"[!] siSocmedSpy: Gagal melakukan pencarian sosial media - {e}")

class siBingDorker:
    def jalan(self, domain):
        try:
            print(f"[*] siBingDorker: Melakukan dorking Bing untuk file sensitif di domain {domain}")
            queries = [f"site:{domain} filetype:env", f"site:{domain} filetype:log"]
            hasil = []
            for q in queries:
                print(f"  [+] Query: {q}")
                url = f"https://www.bing.com/search?q={q}"
                r = requests.get(url, headers=HEADERS())
                found = re.findall(r"https?://[^\s\"']+", r.text)
                hasil.extend(found)
                print(f"    [-] {len(found)} URL ditemukan untuk query ini")
            hasil_unik = list(set(hasil))
            LOGS.append({"bing_dork": hasil_unik})
            print(f"[✓] Total unik hasil dorking Bing: {len(hasil_unik)}")
        except Exception as e:
            print(f"[!] siBingDorker: Gagal melakukan dorking Bing - {e}")

class siLoginPageSniper:
    def jalan(self, domain):
        try:
            print(f"[*] siLoginPageSniper: Mencari halaman login pada domain {domain}")
            logins = []
            hints = ["admin", "login", "signin", "dashboard", "cpanel"]
            for hint in hints:
                url = f"https://{domain}/{hint}"
                try:
                    r = requests.get(url, timeout=5)
                    if r.status_code == 200 and "password" in r.text.lower():
                        logins.append(url)
                        print(f"[✓] Halaman login terdeteksi: {url}")
                except Exception as e:
                    print(f"[!] Gagal akses {url} - {e}")
            if not logins:
                print(f"[!] Tidak ditemukan halaman login dari path umum")
            LOGS.append({"login_pages": logins})
        except Exception as e:
            print(f"[!] siLoginPageSniper: Gagal proses pencarian halaman login - {e}")

class siOpenRedirectHunter:
    def jalan(self, domain):
        try:
            print(f"[*] siOpenRedirectHunter: Mencoba mendeteksi kerentanan Open Redirect pada domain {domain}")
            param = ["redirect", "next", "url"]
            hasil = []
            for p in param:
                test = f"https://{domain}/?{p}=https://evil.com"
                try:
                    r = requests.get(test, allow_redirects=False, timeout=5)
                    location = r.headers.get("Location", "")
                    if "evil.com" in location:
                        hasil.append(test)
                        print(f"[✓] Potensi Open Redirect ditemukan pada: {test}")
                except Exception as e:
                    print(f"[!] Gagal mengakses {test} - {e}")
            if not hasil:
                print(f"[!] Tidak ditemukan kerentanan Open Redirect.")
            LOGS.append({"open_redirect": hasil})
        except Exception as e:
            print(f"[!] siOpenRedirectHunter: Error utama - {e}")

class siFaviconHashHunter:
    def jalan(self, domain):
        try:
            print(f"[*] siFaviconHashHunter: Mengambil favicon dan menghitung hash untuk {domain}")
            r = requests.get(f"https://{domain}/favicon.ico", timeout=5)
            import hashlib
            hash = hashlib.md5(r.content).hexdigest()
            LOGS.append({"favicon_hash": hash})
            print(f"[✓] Hash favicon untuk {domain}: {hash}")
        except Exception as e:
            print(f"[!] siFaviconHashHunter: Gagal menghitung hash favicon - {e}")

class siEmailPatternCrafter:
    def jalan(self, domain):
        try:
            import smtplib
            print(f"[*] siEmailPatternCrafter: Mencoba membuat dan menguji pola email pada domain {domain}")
            pola = ["admin", "ceo", "info", "sales"]
            hasil = []
            for p in pola:
                email = f"{p}@{domain}"
                try:
                    server = smtplib.SMTP("smtp." + domain, 25, timeout=5)
                    code = server.helo()[0]
                    if code == 250:
                        hasil.append(email)
                        print(f"[✓] Email valid terdeteksi: {email}")
                    server.quit()
                except Exception as e:
                    print(f"[!] Gagal verifikasi {email} - {e}")
            if not hasil:
                print(f"[!] Tidak ditemukan email valid pada domain ini.")
            LOGS.append({"emails_found": hasil})
        except Exception as e:
            print(f"[!] siEmailPatternCrafter: Gagal meng-craft email pattern - {e}")

class siGraphBuilder:
    def jalan(self, domain):
        try:
            print(f"[*] siGraphBuilder: Membangun grafik relasi dari hasil pencarian pada domain {domain}")
            edges = []
            for log in LOGS:
                for k, v in log.items():
                    edges.append((domain, k))
            LOGS.append({"graph_edges": edges})
            print(f"[✓] Edge relasi berhasil dibangun: {len(edges)} edge terhubung.")
        except Exception as e:
            print(f"[!] siGraphBuilder: Gagal membangun graph - {e}")

class siAutoExploitStarter:
    def jalan(self, domain):
        try:
            print(f"[*] siAutoExploitStarter: Memulai otomatisasi XSS testing pada hasil direktori dari domain {domain}")
            found = False
            for log in LOGS:
                if "dir" in log:
                    for u in log["dir"]:
                        test = f"{u}?q=<script>alert(1)</script>"
                        try:
                            r = requests.get(test)
                            if "<script>alert(1)" in r.text:
                                hasil = f"KEPOCOL di {u}"
                                LOGS.append({"xss_auto": hasil})
                                print(f"[✓] XSS ditemukan! -> {hasil}")
                                found = True
                        except Exception as e:
                            print(f"[!] Gagal eksploitasi XSS di {u} - {e}")
            if not found:
                print(f"[!] Tidak ditemukan kemungkinan XSS pada direktori yang ada.")
        except Exception as e:
            print(f"[!] siAutoExploitStarter error: {e}")

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
