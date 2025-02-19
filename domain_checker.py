import asyncio
import aiohttp
import dns.asyncresolver
import socket
import ssl
import time
import datetime
import whois
import streamlit as st
from urllib.parse import urlparse

# --- WHOIS Functions ---
WHOIS_CACHE = {}

def get_whois_info(domain):
    global WHOIS_CACHE
    if domain in WHOIS_CACHE:
        return WHOIS_CACHE[domain]
    time.sleep(0.2)
    max_attempts = 3
    backoff_factor = 0.5
    for attempt in range(max_attempts):
        try:
            if attempt > 0:
                time.sleep(backoff_factor * (2 ** (attempt - 1)))
            w = whois.whois(domain)
            registrar = w.registrar if hasattr(w, 'registrar') else ""
            creation_date = w.creation_date
            expiration_date = w.expiration_date
            name_servers = w.name_servers if hasattr(w, 'name_servers') else ""
            if isinstance(name_servers, list):
                name_servers = ", ".join(name_servers)
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            if isinstance(expiration_date, list):
                expiration_date = expiration_date[0]
            result = {
                "registrar": registrar,
                "creation_date": creation_date,
                "expiration_date": expiration_date,
                "name_servers": name_servers,
                "error": ""
            }
            WHOIS_CACHE[domain] = result
            return result
        except Exception as e:
            error_str = str(e)
            if "reset" in error_str.lower():
                error_str = "Connection reset error. Please try again later."
            if attempt == max_attempts - 1:
                result = {"registrar": "", "creation_date": "", "expiration_date": "", "name_servers": "", "error": error_str}
                WHOIS_CACHE[domain] = result
                return result

async def process_whois_domain(domain):
    info = await asyncio.to_thread(get_whois_info, domain)
    return (
        domain,
        info.get("registrar", ""),
        info.get("creation_date", ""),
        info.get("expiration_date", ""),
        info.get("name_servers", ""),
        info.get("error", "")
    )

async def run_whois_checks(domains):
    tasks = [process_whois_domain(domain) for domain in domains]
    results = []
    total = len(tasks)
    progress_bar = st.progress(0)
    for i, coro in enumerate(asyncio.as_completed(tasks), start=1):
        result = await coro
        results.append(result)
        progress_bar.progress(int((i / total) * 100))
    return results

# --- HTTP Check Functions ---
http_headers = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/90.0.4430.93 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5"
}

async def check_http_domain(domain, timeout, retries, session, headers, semaphore):
    url = "http://" + domain if not domain.startswith(("http://", "https://")) else domain
    attempt = 0
    error_message = ""
    response_time = None
    redirect_info = ""
    redirected = "No"
    start_time = time.perf_counter()
    def normalize_url(url):
        parsed = urlparse(url)
        netloc = parsed.netloc.lower().lstrip("www.")
        path = parsed.path.rstrip("/") or "/"
        return netloc, path, parsed.query
    while attempt < retries:
        attempt += 1
        try:
            async with semaphore:
                async with session.get(url, headers=headers, timeout=timeout) as response:
                    response_time = time.perf_counter() - start_time
                    status = response.status
                    text = await response.text()
                    snippet = text[:200]
                    if response.history:
                        redirects = [str(resp.url) for resp in response.history] + [str(response.url)]
                        redirect_info = " -> ".join(redirects)
                    else:
                        redirect_info = "No redirect"
                    if normalize_url(url) != normalize_url(str(response.url)):
                        redirected = "Yes"
                    return (
                        domain, status, snippet, round(response_time, 2),
                        attempt, "Yes", redirect_info, redirected
                    )
        except Exception as e:
            error_message = str(e)
            await asyncio.sleep(0.5)
    response_time = time.perf_counter() - start_time
    snippet = f"Error occurred: {error_message}"
    return (domain, None, snippet, round(response_time, 2), attempt, "No", "No redirect", "No")

async def run_http_checks(domains, timeout, concurrency, retries):
    results = []
    semaphore = asyncio.Semaphore(concurrency)
    async with aiohttp.ClientSession() as session:
        tasks = [check_http_domain(domain, timeout, retries, session, http_headers, semaphore) for domain in domains]
        progress_bar = st.progress(0)
        total = len(tasks)
        completed = 0
        for future in asyncio.as_completed(tasks):
            result = await future
            results.append(result)
            completed += 1
            progress_bar.progress(int((completed / total) * 100))
    return results

# --- DNS Check Functions ---
async def get_dns_record_for_domain(domain, record_types):
    if not domain or '.' not in domain:
        return domain, {rtype: "Invalid domain format" for rtype in record_types}
    records = {}
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5
    resolver.nameservers = ['8.8.8.8', '1.1.1.1']
    cname_result = None
    try:
        cname_answer = await resolver.resolve(domain, "CNAME")
        cname_result = [rdata.to_text() for rdata in cname_answer]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout):
        cname_result = None
    except Exception:
        cname_result = None
    for rtype in record_types:
        try:
            if rtype in ["A", "AAAA"]:
                if cname_result:
                    target = cname_result[0].rstrip('.')
                    answer = await resolver.resolve(target, rtype)
                    record_list = [rdata.to_text() for rdata in answer]
                    record_list = [f"{rec} (Inherited from {target})" for rec in record_list]
                else:
                    answer = await resolver.resolve(domain, rtype)
                    record_list = [rdata.to_text() for rdata in answer]
                records[rtype] = record_list if record_list else "No records found"
            elif rtype == "MX":
                answer = await resolver.resolve(domain, rtype)
                mx_records = []
                for rdata in answer:
                    target = str(rdata.exchange).rstrip('.')
                    mx_cname = None
                    try:
                        mx_cname_answer = await resolver.resolve(target, "CNAME")
                        mx_cname = [rd.to_text() for rd in mx_cname_answer]
                    except Exception:
                        mx_cname = None
                    mx_str = f"Priority {rdata.preference}: {target}"
                    if mx_cname:
                        mx_str += " (Inherited from CNAME)"
                    mx_records.append(mx_str)
                records[rtype] = mx_records if mx_records else "No records found"
            else:
                answer = await resolver.resolve(domain, rtype)
                record_list = [rdata.to_text() for rdata in answer]
                records[rtype] = record_list if record_list else "No records found"
        except dns.resolver.NoAnswer:
            records[rtype] = "No records found"
        except dns.resolver.NXDOMAIN:
            records[rtype] = "Domain does not exist"
        except dns.resolver.Timeout:
            records[rtype] = "Lookup timed out"
        except Exception as e:
            records[rtype] = f"Error: {str(e)}"
    if cname_result and "CNAME" not in record_types:
        records["CNAME_Inheritance"] = "Inherited from CNAME"
    return domain, records

async def run_dns_checks(domains, record_types, progress_callback=None):
    results = {}
    tasks = [get_dns_record_for_domain(domain, record_types) for domain in domains]
    total = len(tasks)
    completed = 0
    for task in asyncio.as_completed(tasks):
        domain, result = await task
        results[domain] = result
        completed += 1
        if progress_callback:
            progress_callback(completed, total)
    return results

# --- TLS/SSL Certificate Check Functions ---
def get_certificate_info(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                expiry_date_str = cert.get('notAfter')
                if not expiry_date_str:
                    return None, None, "Certificate does not have an expiration date"
                expiry_date = datetime.datetime.strptime(expiry_date_str, "%b %d %H:%M:%S %Y %Z")
                now = datetime.datetime.utcnow()
                days_until_expiry = (expiry_date - now).days
                return expiry_date_str, days_until_expiry, ""
    except Exception as e:
        return None, None, str(e)

async def process_certificate_check(domain):
    return await asyncio.to_thread(get_certificate_info, domain)

async def process_cert_domain(domain):
    cert_expiry_date, days_until_expiry, cert_error = await process_certificate_check(domain)
    return (
        domain,
        cert_expiry_date if cert_expiry_date else "",
        days_until_expiry if days_until_expiry is not None else "",
        cert_error
    )

async def run_certificate_checks(domains):
    tasks = [process_cert_domain(domain) for domain in domains]
    results = []
    total = len(tasks)
    progress_bar = st.progress(0)
    for i, task in enumerate(asyncio.as_completed(tasks), start=1):
        result = await task
        results.append(result)
        progress_bar.progress(int((i / total) * 100))
    return results

# --- Advanced Check Functions ---
def expand_domains(domains, include_www_variant, include_naked_variant):
    expanded = set()
    for domain in domains:
        d = domain.strip()
        if not d:
            continue
        expanded.add(d)
        if include_www_variant and not d.startswith("www."):
            expanded.add("www." + d)
        if include_naked_variant and d.startswith("www."):
            expanded.add(d[4:])
    return list(expanded)

async def process_all_in_one(domain, timeout, retries, dns_record_types, whois_enabled, cert_enabled, wildcard_enabled, session, semaphore):
    result = {"Domain": domain}
    if whois_enabled:
        whois_info = await asyncio.to_thread(get_whois_info, domain)
        result["Registrar"] = whois_info.get("registrar", "")
        result["WHOIS Creation Date"] = whois_info.get("creation_date", "")
        result["WHOIS Expiration Date"] = whois_info.get("expiration_date", "")
        result["Name Servers"] = whois_info.get("name_servers", "")
        result["WHOIS Error"] = whois_info.get("error", "")
    http_result = await check_http_domain(domain, timeout, retries, session, http_headers, semaphore)
    (_, http_status, http_snippet, http_response_time, http_attempts,
     http_response_received, http_redirect_history, http_redirected) = http_result
    result["HTTP Status"] = http_status
    result["HTTP Snippet"] = http_snippet
    result["HTTP Response Time (s)"] = http_response_time
    result["HTTP Attempts"] = http_attempts
    result["Response Received"] = http_response_received
    result["Redirect History"] = http_redirect_history
    result["Redirected"] = http_redirected
    if dns_record_types:
        dns_result = await get_dns_record_for_domain(domain, dns_record_types)
        dns_records = dns_result[1]
        dns_summary = ", ".join(
            [f"{rtype}: {', '.join(val) if isinstance(val, list) else val}" for rtype, val in dns_records.items()]
        )
        result["DNS Records"] = dns_summary
        recursive_dns = await get_recursive_dns_chain(domain, dns_record_types)
        result["Recursive DNS Chain"] = recursive_dns
    if cert_enabled:
        cert_expiry_date, days_until_expiry, cert_error = await process_certificate_check(domain)
        result["Certificate Expiry Date"] = cert_expiry_date if cert_expiry_date else ""
        result["Days Until Expiry"] = days_until_expiry if days_until_expiry is not None else ""
        result["Certificate Error"] = cert_error
    if wildcard_enabled:
        # Note: check_wildcard_dns can be defined similarly if needed.
        pass
    return result

async def get_recursive_dns_chain(domain, record_types):
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5
    resolver.nameservers = ['8.8.8.8', '1.1.1.1']
    output_lines = []
    output_lines.append(f"DNS Resolution for {domain}")
    output_lines.append("    ")
    if "A" in record_types or "AAAA" in record_types:
        output_lines.append("A/AAAA Resolution:")
        chain_lines = []
        current = domain
        chain_lines.append(f"Start Domain: {current}")
        last_cname = None
        while True:
            try:
                cname_answer = await resolver.resolve(current, "CNAME")
                cname_list = [rdata.to_text() for rdata in cname_answer]
                cname_value = cname_list[0]
                chain_lines.append(f"CNAME: {cname_value} (inherited from {current})")
                last_cname = current = cname_value.rstrip('.')
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout):
                break
            except Exception as e:
                chain_lines.append(f"CNAME: Error: {str(e)}")
                break
        if "A" in record_types:
            try:
                a_answer = await resolver.resolve(current, "A")
                a_recs = [rdata.to_text() for rdata in a_answer]
                if last_cname:
                    chain_lines.append(f"A Records (inherited from {current}): {', '.join(a_recs)}")
                else:
                    chain_lines.append(f"A Records: {', '.join(a_recs)}")
            except Exception as e:
                chain_lines.append(f"A Records: Error: {str(e)}")
        if "AAAA" in record_types:
            try:
                aaaa_answer = await resolver.resolve(current, "AAAA")
                aaaa_recs = [rdata.to_text() for rdata in aaaa_answer]
                if last_cname:
                    chain_lines.append(f"AAAA Records (inherited from {current}): {', '.join(aaaa_recs)}")
                else:
                    chain_lines.append(f"AAAA Records: {', '.join(aaaa_recs)}")
            except Exception as e:
                chain_lines.append(f"AAAA Records: Error: {str(e)}")
        for cl in chain_lines:
            output_lines.append("  - " + cl)
        output_lines.append("")
    # Additional record types (e.g., MX) can be processed here.
    return "\n".join(output_lines)

async def run_all_in_one_checks(domains, timeout, concurrency, retries, dns_record_types, whois_enabled, cert_enabled, wildcard_enabled):
    results = []
    semaphore = asyncio.Semaphore(concurrency)
    async with aiohttp.ClientSession() as session:
        tasks = [
            process_all_in_one(domain, timeout, retries, dns_record_types, whois_enabled, cert_enabled, wildcard_enabled, session, semaphore)
            for domain in domains
        ]
        progress_bar = st.progress(0)
        total = len(tasks)
        completed = 0
        for future in asyncio.as_completed(tasks):
            result = await future
            results.append(result)
            completed += 1
            progress_bar.progress(int((completed / total) * 100))
    return results
