import ssl 

import socket 

from datetime import datetime 

 

print("=" * 50) 

print("SSL/TLS CERTIFICATE INSPECTOR") 

print("=" * 50) 

 

hostname = input("Enter website (example: google.com): ").strip() 

 

try: 

    context = ssl.create_default_context() 

 

    with socket.create_connection((hostname, 443), timeout=5) as sock: 

        with context.wrap_socket(sock, server_hostname=hostname) as ssock: 

            cert = ssock.getpeercert() 

 

    print("\nCertificate Information") 

    print("-" * 50) 

 

    subject = dict(x[0] for x in cert["subject"]) 

    issuer = dict(x[0] for x in cert["issuer"]) 

 

    print(f"Common Name : {subject.get('commonName', 'Unknown')}") 

    print(f"Issuer      : {issuer.get('commonName', 'Unknown')}") 

 

    expires = cert["notAfter"] 

    expire_date = datetime.strptime(expires, "%b %d %H:%M:%S %Y %Z") 

 

    print(f"Expires     : {expire_date}") 

 

    days_left = (expire_date - datetime.utcnow()).days 

 

    print(f"Days Left   : {days_left}") 

 

    if days_left < 0: 

        print("\n[!] Certificate EXPIRED!") 

    elif days_left < 30: 

        print("\n[!] Certificate expires within 30 days!") 

    else: 

        print("\n[+] Certificate is valid.") 

 

except Exception as e: 

    print(f"\nError: {e}") 

