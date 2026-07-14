#!/usr/bin/env python3 

 

import re 

from urllib.parse import urlparse 

 

import requests 

 

print("=" * 60) 

print("      CYBERLAB WEB TECHNOLOGY FINGERPRINTER") 

print("=" * 60) 

 

target = input("Enter website, example.com: ").strip() 

 

if not target.startswith(("http://", "https://")): 

    target = "https://" + target 

 

try: 

    response = requests.get( 

        target, 

        timeout=10, 

        allow_redirects=True, 

        headers={"User-Agent": "CyberLab-Web-Fingerprinter/1.0"}, 

    ) 

 

    print("\nBasic Information") 

    print("-" * 60) 

    print(f"Requested URL : {target}") 

    print(f"Final URL     : {response.url}") 

    print(f"Status Code   : {response.status_code}") 

    print(f"Host          : {urlparse(response.url).hostname}") 

 

    print("\nDetected Technologies") 

    print("-" * 60) 

 

    detected = [] 

 

    server = response.headers.get("Server") 

    if server: 

        detected.append(f"Web Server: {server}") 

 

    powered_by = response.headers.get("X-Powered-By") 

    if powered_by: 

        detected.append(f"X-Powered-By: {powered_by}") 

 

    generator_match = re.search( 

        r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', 

        response.text, 

        re.IGNORECASE, 

    ) 

    if generator_match: 

        detected.append(f"Generator: {generator_match.group(1)}") 

 

    html = response.text.lower() 

    headers_text = str(response.headers).lower() 

 

    signatures = { 

        "WordPress": ["wp-content", "wp-includes", "wordpress"], 

        "Drupal": ["drupal", "sites/default/files"], 

        "Joomla": ["joomla", "com_content"], 

        "React": ["react", "__react"], 

        "Angular": ["ng-version", "angular"], 

        "Vue.js": ["vue.js", "__vue__"], 

        "Bootstrap": ["bootstrap"], 

        "jQuery": ["jquery"], 

        "Cloudflare": ["cloudflare", "cf-ray"], 

        "PHP": ["php", "phpsessid"], 

        "ASP.NET": ["asp.net", "aspnet"], 

        "Nginx": ["nginx"], 

        "Apache": ["apache"], 

        "Microsoft IIS": ["microsoft-iis", "iis"], 

    } 

 

    for technology, indicators in signatures.items(): 

        if any( 

            indicator in html or indicator in headers_text 

            for indicator in indicators 

        ): 

            detected.append(technology) 

 

    if detected: 

        for item in sorted(set(detected)): 

            print(f"[+] {item}") 

    else: 

        print("[-] No obvious technology signatures detected.") 

 

    print("\nInteresting Headers") 

    print("-" * 60) 

 

    header_names = [ 

        "Server", 

        "X-Powered-By", 

        "Via", 

        "CF-Ray", 

        "X-Generator", 

        "Set-Cookie", 

    ] 

 

    for header in header_names: 

        value = response.headers.get(header) 

        if value: 

            print(f"{header:<18}: {value}") 

 

except requests.exceptions.SSLError as error: 

    print(f"\nSSL error: {error}") 

 

except requests.exceptions.Timeout: 

    print("\nThe request timed out.") 

 

except requests.exceptions.ConnectionError: 

    print("\nConnection failed. Check the website address.") 

 

except requests.exceptions.RequestException as error: 

    print(f"\nRequest failed: {error}") 

 

except KeyboardInterrupt: 

    print("\nScan cancelled.") 