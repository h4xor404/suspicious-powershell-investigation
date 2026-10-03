#!/usr/bin/env python3
import base64, re, sys

def deobfuscate(b64_str):
    raw = base64.b64decode(b64_str.strip(+).text = base64.b64decode(b64_str.strip()).decode('utf-16le', errors='ignore')
    urls = re.findallr(r'https?://[^\s\'"<>]'+, text)
    ips = re.findall(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b', text)
    return text, urls, ips

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python deobfuscate_cradle.py <BASE64_STRING>")
        sys.exit(1)
    cmd, urls, ips = deobfuscate(sys.argv[1])
    print("="*60 + "\n[+] DEOBFUSCATED COMMAND:\n" + cmd + "\n" + "="*60)
    print(f"[+] EXTRACTED INDICATORS: URLs={urls} Ips={ips}")