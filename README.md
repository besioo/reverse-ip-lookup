# Reverse IP Lookup

Reverse IP reconnaissance tool for discovering domains hosted on the same IP address using VirusTotal and SecurityTrails APIs.

## Features
- Reverse IP lookup using:
  - VirusTotal
  - SecurityTrails
- Scroll & cursor pagination support
- Deduplication of results
- Proxy support (HTTP / SOCKS)
- SSL verification control (Burp-friendly)
- Automatic API key rotation for SecurityTrails
- Results saved to file

---

## Requirements
- Python 3.8+
- API keys for:
  - :contentReference[oaicite:0]{index=0}
  - :contentReference[oaicite:1]{index=1}

Install dependencies:
```bash
pip install requests
