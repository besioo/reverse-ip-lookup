import requests
import json
import argparse
import urllib3

# Disable urllib3 warnings for unverified HTTPS requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


API_KEYS = []  # SecurityTrails API keys ["A","B"]

VIRUSTOTAL_API_KEY = ""   # VirusTotal API Key

# Parse arguments
parser = argparse.ArgumentParser(description='Reverse IP Lookup Tool')
parser.add_argument('ip', help='IP address to lookup')
parser.add_argument('--proxy', help='Proxy URL (e.g., http://127.0.0.1:8080 or socks5://127.0.0.1:1080)')
parser.add_argument('-o', '--output', help='Output file path (default: {ip}.results.txt)')
parser.add_argument('--no-verify', action='store_true', help='Disable SSL certificate verification (automatically disabled when using proxy)')
args = parser.parse_args()

ip = args.ip
proxy = args.proxy
output_file = args.output if args.output else f"{ip}.results.txt"
# Disable SSL verification when using proxy (common with intercepting proxies like Burp)
# User can override with --no-verify flag (which also disables verification)
verify_ssl = False if proxy else (not args.no_verify)
query = f"SELECT domain.hostname FROM hosts WHERE dns.a.value.ip='{ip}' OR dns.a.old.value.ip='{ip}'"

# Setup proxy dict for requests
proxies = None
if proxy:
    proxies = {
        'http': proxy,
        'https': proxy
    }

# Track unique hostnames to avoid duplicates
seen_hostnames = set()

def write_results(records, source="securitytrails"):
    """Write unique results to the output file"""
    unique_count = 0
    with open(output_file, "a", encoding="utf-8") as f:
        for record in records:
            if source == "securitytrails":
                hostname = record["domain"]["hostname"]
            elif source == "virustotal":
                hostname = record.get("hostname") or record.get("host_name")
            if hostname and hostname not in seen_hostnames:
                seen_hostnames.add(hostname)
                f.write(hostname + "\n")
                unique_count += 1
    return unique_count

def virustotal_lookup(cursor=None, page=1):
    """Perform reverse IP lookup using VirusTotal API with recursive pagination"""
    if page == 1:
        print("[+] Performing VirusTotal lookup...")
    
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}/resolutions"
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }
    
    # Add cursor parameter for pagination
    params = {}
    if cursor:
        params["cursor"] = cursor
    
    try:
        response = requests.get(url, headers=headers, params=params, proxies=proxies, timeout=30, verify=verify_ssl)
        
        if response.status_code == 200:
            data = response.json()
            records = data.get("data", [])
            
            if records:
                unique_count = write_results(records, source="virustotal")
                print(f"[+] VirusTotal page {page}: found {len(records)} domains ({unique_count} unique)")
                
                # Check for next page using cursor in meta.links
                meta = data.get("meta", {})
                links = meta.get("links", {})
                next_cursor = links.get("next")
                
                if next_cursor:
                    # Recursively fetch next page
                    return virustotal_lookup(cursor=next_cursor, page=page + 1)
                else:
                    print(f"[+] VirusTotal lookup completed ({page} page(s) total)")
                    return
            else:
                if page == 1:
                    print("[+] VirusTotal: No domains found")
                else:
                    print(f"[+] VirusTotal lookup completed ({page} page(s) total)")
                return
                
        elif response.status_code == 404:
            if page == 1:
                print("[+] VirusTotal: No data available for this IP")
            return
        elif response.status_code == 429:
            print("[!] VirusTotal: Rate limit exceeded, skipping remaining pages...")
            return
        else:
            print(f"[!] VirusTotal API error: {response.status_code}")
            print(f"    Response: {response.text[:200]}")
            return
            
    except requests.exceptions.RequestException as e:
        print(f"[!] VirusTotal lookup failed: {str(e)}")
        return
    except Exception as e:
        print(f"[!] VirusTotal lookup error: {str(e)}")
        return

def get_api_key():
    """Get a working SecurityTrails API key by testing available keys"""
    timeout = 30 if proxy else 10  # Longer timeout when using proxy
    last_error = None
    
    for idx, api_key in enumerate(API_KEYS, 1):
        try:
            url = f"https://api.securitytrails.com/v1/ping?apikey={api_key}"
            headers = {"Accept": "application/json"}
            response = requests.get(url, headers=headers, proxies=proxies, timeout=timeout, verify=verify_ssl)
            if response.status_code == 200:
                if proxy and idx > 1:
                    print(f"[+] Found working API key (tested {idx} keys)")
                return api_key
            elif response.status_code == 401:
                # Invalid API key, try next one
                continue
            else:
                last_error = f"HTTP {response.status_code}: {response.text[:100]}"
                continue
        except requests.exceptions.ProxyError as e:
            last_error = f"Proxy error: {str(e)}"
            print(f"[!] Proxy connection failed: {e}")
            print("[!] Please check your proxy settings and ensure the proxy is running")
            break
        except requests.exceptions.SSLError as e:
            last_error = f"SSL error: {str(e)}"
            print(f"[!] SSL error with proxy: {e}")
            break
        except requests.exceptions.ConnectionError as e:
            last_error = f"Connection error: {str(e)}"
            print(f"[!] Connection error: {e}")
            if proxy:
                print("[!] Unable to connect through proxy. Check if proxy is accessible.")
            break
        except requests.exceptions.Timeout as e:
            last_error = f"Timeout: {str(e)}"
            if idx == 1:
                print(f"[!] Request timeout (using proxy: {proxy})")
            continue
        except Exception as e:
            last_error = f"Unexpected error: {str(e)}"
            if idx == 1:
                print(f"[!] Error testing API key: {e}")
            continue
    
    print("[-] No Valid API key found")
    if last_error:
        print(f"[-] Last error: {last_error}")
    exit(1)

def securitytrails_lookup():
    """Perform reverse IP lookup using SecurityTrails API with scroll pagination"""
    print("[+] Starting SecurityTrails lookup...")
    
    # Get working API key
    api_key = get_api_key()
    
    # Base URL for SecurityTrails API
    base_url = "https://api.securitytrails.com/v1/query/scroll/"
    headers = {
        "APIKEY": api_key,
        "Content-Type": "application/json"
    }
    
    # Initial request to start scroll query
    print("[+] Sending initial query request...")
    query_data = {"query": query}
    
    try:
        response = requests.post(base_url, json=query_data, headers=headers, proxies=proxies, timeout=30, verify=verify_ssl)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"[-] Initial request failed: {e}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"    Status Code: {e.response.status_code}")
            print(f"    Response: {e.response.text[:500]}")
        return
    
    # Check if response has content
    if not response.text or not response.text.strip():
        print(f"[-] Empty response received from initial request")
        print(f"    Status Code: {response.status_code}")
        print(f"    Headers: {dict(response.headers)}")
        return
    
    # Parse JSON response
    try:
        response_data = response.json()
    except json.JSONDecodeError as e:
        print(f"[-] Failed to parse JSON response: {e}")
        print(f"    Status Code: {response.status_code}")
        print(f"    Content-Type: {response.headers.get('Content-Type', 'Unknown')}")
        print(f"    Response preview: {response.text[:500]}")
        # Check if it's an HTML error page
        if response.text.strip().startswith('<'):
            print("    Note: Response appears to be HTML, not JSON")
        return
    
    # Extract and display total results
    total_results = response_data.get("total", {}).get("value", 0)
    print(f"[+] Total Results: {total_results}")
    
    # Write first batch of records
    records = response_data.get("records", [])
    if records:
        unique_count = write_results(records)
        print(f"[+] Wrote {len(records)} records from initial request ({unique_count} unique)")
    
    # Get scroll ID for pagination
    scroll_id = response_data.get("id")
    if not scroll_id:
        print("[+] No scroll ID returned, query complete")
        return
    
    # Continue fetching remaining results using scroll pagination
    request_number = 2
    while scroll_id:
        # Get fresh API key for each request (in case previous one expires)
        api_key = get_api_key()
        headers["APIKEY"] = api_key
        
        # Construct scroll URL
        scroll_url = f"{base_url}{scroll_id}"
        print(f"[+] Fetch Request #{request_number}: {scroll_url}")
        
        try:
            response = requests.get(scroll_url, headers=headers, proxies=proxies, timeout=30, verify=verify_ssl)
            # 204 No Content is a valid response meaning no more results
            if response.status_code == 204:
                print("[+] Received 204 No Content - no more results to fetch")
                break
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            print(f"[-] Scroll request failed: {e}")
            if hasattr(e, 'response') and e.response is not None:
                print(f"    Status Code: {e.response.status_code}")
                print(f"    Response: {e.response.text[:500]}")
            else:
                print(f"    Error details: {str(e)}")
            exit(1)
        
        # Check if response has content (skip for 204 which is already handled above)
        if not response.text or not response.text.strip():
            # If status is 204, we already handled it above, but double-check
            if response.status_code == 204:
                print("[+] No more results (204 No Content)")
                break
            print(f"[-] Empty response received from scroll request")
            print(f"    Status Code: {response.status_code}")
            print(f"    Headers: {dict(response.headers)}")
            exit(1)
        
        # Parse JSON response
        try:
            response_data = response.json()
        except json.JSONDecodeError as e:
            # If status is 204, empty response is expected
            if response.status_code == 204:
                print("[+] No more results (204 No Content)")
                break
            print(f"[-] Failed to parse JSON response: {e}")
            print(f"    Status Code: {response.status_code}")
            print(f"    Content-Type: {response.headers.get('Content-Type', 'Unknown')}")
            print(f"    Response preview: {response.text[:500]}")
            # Check if it's an HTML error page
            if response.text.strip().startswith('<'):
                print("    Note: Response appears to be HTML, not JSON")
            exit(1)
        
        # Extract records and scroll ID
        try:
            records = response_data.get("records", [])
            if records:
                unique_count = write_results(records)
                print(f"[+] Wrote {len(records)} records from request #{request_number} ({unique_count} unique)")
            
            scroll_id = response_data.get("id")
            request_number += 1
            
            # If no scroll ID, we've reached the end
            if not scroll_id:
                print("[+] All results fetched, scroll complete")
                break
        except (KeyError, TypeError) as e:
            print(f"[-] Unexpected response format: {e}")
            print(f"    Status Code: {response.status_code}")
            print(f"    Response data: {str(response_data)[:500]}")
            exit(1)
    
    print("[+] SecurityTrails lookup completed")

# Main execution
print(f"[+] Starting reverse IP lookup for {ip}")
if proxy:
    print(f"[+] Using proxy: {proxy}")
    print("[!] SSL verification disabled (automatic when using proxy)")
elif not verify_ssl:
    print("[!] SSL verification disabled")
print(f"[+] Output file: {output_file}")

# SecurityTrails lookup
securitytrails_lookup()

# VirusTotal lookup
virustotal_lookup()

print(f"[+] Results saved to {output_file}")
print(f"[+] Total unique domains found: {len(seen_hostnames)}")


