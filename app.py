from flask import Flask, request, jsonify, render_template
import requests
import base64
import os

app = Flask(__name__)

# Your VirusTotal API Key
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

    # VirusTotal API v3 requires the URL to be base64 encoded
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    headers = {"x-apikey": VT_API_KEY}
    
    try:
        # Query the VirusTotal API
        api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        response = requests.get(api_url, headers=headers)
        
        if response.status_code == 200:
            # Extract the analysis stats
            stats = response.json()['data']['attributes']['last_analysis_stats']
            return jsonify(stats)
        elif response.status_code == 404:
             return jsonify({'error': 'URL not found in VirusTotal database. Try scanning it directly on VT first.'}), 404
        else:
            return jsonify({'error': 'Failed to fetch data from VirusTotal API.'}), 500
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)