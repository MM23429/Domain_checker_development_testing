import streamlit as st
import asyncio
import pandas as pd
import datetime
import io
import time
from domain_checker import (
    run_http_checks, run_dns_checks, run_whois_checks, run_certificate_checks,
    run_all_in_one_checks, expand_domains
)
from subdomain_finder import aggregate_subdomains, verify_subdomains_async

st.set_page_config(page_title="Domain Checker", layout="wide")
st.title("Domain Checker")

tabs = st.tabs([
    "HTTP Check", "DNS Lookup", "WHOIS Check",
    "TLS/SSL Certificate Check", "Advanced Check", "Subdomain Finder"
])

# ----- HTTP Check Tab -----
with tabs[0]:
    st.header("HTTP Check")
    st.markdown("Retrieve HTTP status, response snippet, response time, and redirection details.")
    with st.form("http_form"):
        domains_input_http = st.text_area("Enter one or more domains (one per line):", height=200)
        timeout = st.number_input("Timeout (seconds)", min_value=1, value=10, step=1)
        concurrency = st.number_input("Concurrency", min_value=1, value=20, step=1)
        retries = st.number_input("Retries", min_value=1, value=3, step=1)
        submit_http = st.form_submit_button("Run HTTP Check")
    if submit_http:
        if not domains_input_http.strip():
            st.error("Please enter at least one domain.")
        else:
            domains_http = [line.strip() for line in domains_input_http.splitlines() if line.strip()]
            st.info("Starting HTTP checks...")
            http_results = asyncio.run(run_http_checks(domains_http, timeout, concurrency, retries))
            df_http = pd.DataFrame(
                http_results,
                columns=["Domain", "Status Code", "Response Snippet", "Response Time (s)",
                         "Attempts", "Response Received", "Redirect History", "Redirected"]
            )
            st.write("### HTTP Check Results", df_http)
            st.session_state["http_df"] = df_http
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            st.download_button("Download Table as CSV", df_http.to_csv(index=False),
                               file_name=f"HTTP_Check_Results_{timestamp}.csv", mime="text/csv")
    elif "http_df" in st.session_state:
        st.write("### HTTP Check Results", st.session_state["http_df"])

# ----- DNS Lookup Tab -----
with tabs[1]:
    st.header("DNS Lookup")
    st.markdown("Perform DNS record lookups for specified domains.")
    with st.form("dns_form"):
        domains_input_dns = st.text_area("Enter one or more domains (one per line):", height=150)
        st.markdown("### Select DNS Record Types")
        record_options = ["A", "AAAA", "CNAME", "MX", "NS", "SOA", "TXT"]
        selected_record_types = []
        cols = st.columns(4)
        for i, rtype in enumerate(record_options):
            col = cols[i % 4]
            if col.checkbox(rtype, value=True, key=f"checkbox_{rtype}"):
                selected_record_types.append(rtype)
        submit_dns = st.form_submit_button("Lookup DNS Records")
    if submit_dns:
        if not domains_input_dns.strip():
            st.error("Please enter at least one domain.")
        elif not selected_record_types:
            st.error("Please select at least one DNS record type.")
        else:
            domains_dns = [line.strip() for line in domains_input_dns.splitlines() if line.strip()]
            total_domains = len(domains_dns)
            st.write(f"Processing **{total_domains}** domain(s)...")
            progress_bar = st.progress(0)
            def progress_callback(completed, total):
                progress_bar.progress(int((completed / total) * 100))
            start_time = time.time()
            dns_results = asyncio.run(run_dns_checks(domains_dns, selected_record_types, progress_callback))
            end_time = time.time()
            elapsed_time = end_time - start_time
            domains_per_second = total_domains / elapsed_time if elapsed_time > 0 else 0
            import csv
            csv_output = io.StringIO()
            csv_writer = csv.writer(csv_output)
            header = ["Domain"] + selected_record_types
            if any("CNAME_Inheritance" in recs for recs in dns_results.values()):
                header.append("CNAME_Inheritance")
            csv_writer.writerow(header)
            data_rows = []
            for domain, recs in dns_results.items():
                row = [domain]
                for rtype in selected_record_types:
                    val = recs.get(rtype, "")
                    if isinstance(val, list):
                        val = "; ".join(val)
                    row.append(val)
                if "CNAME_Inheritance" in header:
                    row.append(recs.get("CNAME_Inheritance", ""))
                data_rows.append(row)
                csv_writer.writerow(row)
            csv_data = csv_output.getvalue()
            st.subheader("Statistics")
            st.write(f"**Time Taken:** {elapsed_time:.2f} seconds")
            st.write(f"**Processing Speed:** {domains_per_second:.2f} domains/second")
            st.download_button("Download Table as CSV", data=csv_data,
                               file_name=f"DNS_Lookup_Results_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv", mime="text/csv")
            st.subheader("DNS Results")
            df_dns = pd.DataFrame(data_rows, columns=header)
            st.write(df_dns)
            st.session_state["dns_df"] = df_dns
    elif "dns_df" in st.session_state:
        st.write("DNS Results", st.session_state["dns_df"])

# ----- WHOIS Check Tab -----
with tabs[2]:
    st.header("WHOIS Check")
    st.markdown("Retrieve domain registration details.")
    with st.form("whois_form"):
        domains_input = st.text_area("Enter one or more domains (one per line):", height=200)
        submit_whois = st.form_submit_button("Run WHOIS Check")
    if submit_whois:
        if not domains_input.strip():
            st.error("Please enter at least one domain.")
        else:
            domains = [line.strip() for line in domains_input.splitlines() if line.strip()]
            st.info("Starting WHOIS lookups...")
            whois_results = asyncio.run(run_whois_checks(domains))
            df_whois = pd.DataFrame(
                whois_results,
                columns=["Domain", "Registrar", "WHOIS Creation Date", "WHOIS Expiration Date", "Name Servers", "WHOIS Error"]
            )
            if "WHOIS Error" in df_whois.columns and df_whois["WHOIS Error"].astype(str).str.strip().eq("").all():
                df_whois.drop(columns=["WHOIS Error"], inplace=True)
            st.write("### WHOIS Results", df_whois)
            st.session_state["whois_df"] = df_whois
            st.download_button("Download Table as CSV", df_whois.to_csv(index=False),
                               file_name=f"WHOIS_Results_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv", mime="text/csv")
    elif "whois_df" in st.session_state:
        st.write("### WHOIS Results", st.session_state["whois_df"])

# ----- TLS/SSL Certificate Check Tab -----
with tabs[3]:
    st.header("TLS/SSL Certificate Check")
    st.markdown("Perform TLS/SSL certificate checks for each domain.")
    with st.form("cert_form"):
        domains_input_cert = st.text_area("Enter one or more domains (one per line):", height=200)
        submit_cert = st.form_submit_button("Run TLS/SSL Certificate Check")
    if submit_cert:
        if not domains_input_cert.strip():
            st.error("Please enter at least one domain.")
        else:
            domains_cert = [line.strip() for line in domains_input_cert.splitlines() if line.strip()]
            st.info("Starting TLS/SSL Certificate Check...")
            cert_results = asyncio.run(run_certificate_checks(domains_cert))
            df_cert = pd.DataFrame(
                cert_results,
                columns=["Domain", "Certificate Expiry Date", "Days Until Expiry", "Certificate Error"]
            )
            if "Certificate Error" in df_cert.columns and df_cert["Certificate Error"].astype(str).str.strip().eq("").all():
                df_cert.drop(columns=["Certificate Error"], inplace=True)
            st.write("### TLS/SSL Certificate Check Results", df_cert)
            st.session_state["cert_df"] = df_cert
            st.download_button("Download Table as CSV", df_cert.to_csv(index=False),
                               file_name=f"TLS_SSL_Certificate_Results_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv", mime="text/csv")
    elif "cert_df" in st.session_state:
        st.write("### TLS/SSL Certificate Check Results", st.session_state["cert_df"])

# ----- Advanced Check Tab -----
with tabs[4]:
    st.header("Advanced Check")
    st.markdown("Combine HTTP, DNS, WHOIS, and TLS/SSL lookups into one comprehensive report.")
    with st.form("all_form"):
        domains_input_all = st.text_area("Enter one or more domains (one per line):", height=200)
        include_www_variant = st.checkbox("Include www variant for naked domains", value=False, key="include_www")
        include_naked_variant = st.checkbox("Include naked domain for www domains", value=False, key="include_naked")
        wildcard_enabled = st.checkbox("Check for wildcard DNS", value=False, key="check_wildcard")
        whois_enabled = st.checkbox("Enable WHOIS Lookup", value=False, key="all_whois_enabled")
        cert_enabled = st.checkbox("Enable TLS/SSL Certificate Check", value=False, key="all_cert_enabled")
        st.markdown("### Select DNS Record Types")
        record_options_all = ["A", "AAAA", "CNAME", "MX", "NS", "SOA", "TXT"]
        selected_dns_all = []
        cols = st.columns(4)
        for i, rtype in enumerate(record_options_all):
            col = cols[i % 4]
            if col.checkbox(rtype, value=True, key=f"all_checkbox_{rtype}"):
                selected_dns_all.append(rtype)      
        timeout_all = st.number_input("HTTP Timeout (seconds)", min_value=1, value=10, step=1)
        concurrency_all = st.number_input("HTTP Concurrency", min_value=1, value=20, step=1)
        retries_all = st.number_input("HTTP Retries", min_value=1, value=3, step=1)
        submit_all = st.form_submit_button("Run Advanced Check")
    if submit_all:
        if not domains_input_all.strip():
            st.error("Please enter at least one domain.")
        else:
            input_domains = [line.strip() for line in domains_input_all.splitlines() if line.strip()]
            domains_all = expand_domains(input_domains, include_www_variant, include_naked_variant)
            enabled_checks = "HTTP"
            if whois_enabled:
                enabled_checks += ", WHOIS"
            if selected_dns_all:
                enabled_checks += ", DNS"
            if cert_enabled:
                enabled_checks += ", TLS/SSL Certificate Check"
            if wildcard_enabled:
                enabled_checks += ", Wildcard DNS Check"
            st.info(f"Starting All In One checks ({enabled_checks})...")
            start_time_all = time.time()
            all_results = asyncio.run(
                run_all_in_one_checks(domains_all, timeout_all, concurrency_all, retries_all, selected_dns_all, whois_enabled, cert_enabled, wildcard_enabled)
            )
            end_time_all = time.time()
            elapsed_all = end_time_all - start_time_all
            st.write(f"**Total Time Taken:** {elapsed_all:.2f} seconds")
            columns = ["Domain", "HTTP Status"]
            if cert_enabled:
                columns.extend(["Certificate Expiry Date", "Days Until Expiry"])
            if selected_dns_all:
                columns.extend(["DNS Records", "Recursive DNS Chain"])
            if whois_enabled:
                columns.extend(["Registrar", "WHOIS Creation Date", "WHOIS Expiration Date", "Name Servers"])
            if wildcard_enabled:
                columns.append("Wildcard DNS")
            columns.extend(["HTTP Response Time (s)", "HTTP Attempts", "Response Received", "Redirected", "Redirect History", "HTTP Snippet"])
            if whois_enabled:
                columns.append("WHOIS Error")
            if cert_enabled:
                columns.append("Certificate Error")
            df_all = pd.DataFrame(all_results)
            df_all = df_all[[col for col in columns if col in df_all.columns]]
            if "WHOIS Error" in df_all.columns and df_all["WHOIS Error"].astype(str).str.strip().eq("").all():
                df_all.drop(columns=["WHOIS Error"], inplace=True)
            if "Certificate Error" in df_all.columns and df_all["Certificate Error"].astype(str).str.strip().eq("").all():
                df_all.drop(columns=["Certificate Error"], inplace=True)
            st.write("### Advanced Check Results", df_all)
            st.session_state["adv_df"] = df_all
            st.download_button("Download Table as CSV", df_all.to_csv(index=False),
                               file_name=f"Advanced_Check_Results_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv", mime="text/csv")
            st.session_state["all_results"] = all_results
    if "all_results" in st.session_state:
        with st.expander("View Statistics"):
            all_results = st.session_state["all_results"]
            http_times = [res.get("HTTP Response Time (s)") for res in all_results if res.get("HTTP Response Time (s)") is not None]
            if http_times:
                avg_time = sum(http_times) / len(http_times)
                max_time = max(http_times)
                min_time = min(http_times)
                slowest_domains = [res["Domain"] for res in all_results if res.get("HTTP Response Time (s)") == max_time]
                fastest_domains = [res["Domain"] for res in all_results if res.get("HTTP Response Time (s)") == min_time]
                speed = len(http_times) / sum(http_times) if sum(http_times) > 0 else 0
                st.write(f"**Total Domains Processed:** {len(http_times)}")
                st.write(f"**Average HTTP Response Time:** {avg_time:.2f} seconds")
                if fastest_domains:
                    st.write(f"The fastest response was from {fastest_domains[0]} taking {min_time:.2f} seconds.")
                if slowest_domains:
                    st.write(f"The slowest response was from {slowest_domains[0]} taking {max_time:.2f} seconds.")
                st.write(f"**Speed per Domain:** {speed:.2f} domains per second")
            else:
                st.write("No HTTP response times available for advanced statistics.")

# ----- Subdomain Finder Tab -----
with tabs[5]:
    st.header("Subdomain Finder")
    st.markdown(
        """
        Aggregate subdomains using multiple sources:
        - **crt.sh** (certificate transparency logs)
        - **CertSpotter** as fallback
        - **SecurityTrails** (with API key)
        - Brute-force wordlist approach
        """
    )
    domain = st.text_input("Enter target domain (e.g., example.com)", key="subdomain_domain")
    with st.expander("Advanced Options", expanded=False):
        api_key = st.text_input("Enter SecurityTrails API key (optional)", type="password", key="subdomain_api_key")
        wordlist_file = st.file_uploader("Upload brute force wordlist file (optional)", type=["txt"], key="subdomain_wordlist")
    if st.button("Scan", key="subdomain_scan"):
        if not domain:
            st.error("Domain is required!")
        else:
            wordlist = None
            if wordlist_file is not None:
                try:
                    content = wordlist_file.read().decode("utf-8")
                    wordlist = [line.strip() for line in content.splitlines() if line.strip()]
                except Exception as e:
                    st.error(f"Error reading wordlist file: {e}")
            with st.spinner("Aggregating subdomains..."):
                aggregated = aggregate_subdomains(domain, api_key if api_key else None, wordlist)
            st.success(f"Aggregated {len(aggregated)} subdomains (pre-verification)")
            st.write("### Pre-verified Aggregated Subdomains")
            st.write(aggregated)
            pre_verified_log = "\n".join(sorted(aggregated))
            st.download_button(label="Download Pre-Verified Domains Log",
                               data=pre_verified_log,
                               file_name="pre_verified_subdomains.txt",
                               mime="text/plain")
            with st.spinner("Verifying subdomains asynchronously..."):
                verified = asyncio.run(verify_subdomains_async(aggregated))
            st.success(f"Verified {len(verified)} active subdomains")
            st.write("### Verified Active Subdomains")
            st.write(verified)
            verified_results = "\n".join(sorted(verified))
            st.download_button(label="Download Verified Subdomains",
                               data=verified_results,
                               file_name="verified_subdomains.txt",
                               mime="text/plain")
