from flask import Flask, request, jsonify, render_template
import requests
import base64
import os
import socket
from urllib.parse import urlparse

app = Flask(__name__)

# Securely grab the API key from environment variables
VT_API_KEY = os.environ.get('VT_API_KEY')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze_url():
    data = request.json
    url = data.get('url')
    
    if not url:
        return jsonify({'error': 'URL is required'}), 400

    # --- 1. Gather Network & Routing Intelligence ---
    network_data = {'ip': 'N/A', 'country': 'N/A', 'isp': 'N/A'}
    try:
        # Parse the hostname out of the URL (e.g., extracts "google.com" from "https://google.com/search")
        parsed_url = urlparse(url)
        domain = parsed_url.netloc or parsed_url.path.split('/')[0]
        domain = domain.split(':')[0] 
        
        # Resolve the DNS to get the IPv4 address
        ip_address = socket.gethostbyname(domain)
        
        # Query the free IP-API for geolocation and ASN routing data
        geo_response = requests.get(f"http://ip-api.com/json/{ip_address}").json()
        
        if geo_response.get('status') == 'success':
            network_data = {
                'ip': ip_address,
                'country': geo_response.get('country', 'Unknown'),
                'isp': f"{geo_response.get('isp', 'Unknown')} ({geo_response.get('as', '')})"
            }
        else:
            network_data['ip'] = ip_address
    except Exception as e:
        pass # If DNS fails, we just keep the default 'N/A' values and continue

    # --- 2. Gather VirusTotal Threat Intelligence ---
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    headers = {"x-apikey": VT_API_KEY}
    
    try:
        api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        response = requests.get(api_url, headers=headers)
        
        if response.status_code == 200:
            stats = response.json()['data']['attributes']['last_analysis_stats']
            
            # Return a combined JSON payload with both sets of data
            return jsonify({
                'threat_stats': stats,
                'network': network_data
            })
        elif response.status_code == 404:
             return jsonify({'error': 'URL not found in VirusTotal database.'}), 404
        else:
            return jsonify({'error': 'Failed to fetch data from VirusTotal API.'}), 500
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)