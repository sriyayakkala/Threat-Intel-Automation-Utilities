import requests
import json

def check_ip_reputation(ip_address):
    # This uses a public, free Threat Intel API (AbuseIPDB)
    url = 'https://api.abuseipdb.com/api/v2/check'
    
    # Using a public test API key configuration
    headers = {
        'Accept': 'application/json',
        'Key': 'YOUR_API_KEY_HERE' # You can generate a free key on their website
    }
    
    querystring = {
        'ipAddress': ip_address,
        'maxAgeInDays': '90'
    }

    print(f"[*] Querying threat intelligence database for IP: {ip_address}...")
    
    # In a real interview, you explain that you use mock data if the API key isn't provided
    if headers['Key'] == 'YOUR_API_KEY_HERE':
        print("[!] Using simulated threat intelligence response (Add an API key for live deployment).")
        mock_response = {
            "data": {
                "ipAddress": ip_address,
                "isPublic": True,
                "abuseConfidenceScore": 85,
                "countryCode": "CN",
                "usageType": "Data Center/Web Hosting/Transit",
                "totalReports": 412,
                "lastReportedAt": "2026-06-07T12:00:00+00:00"
            }
        }
        display_results(mock_response)
        return

    try:
        response = requests.get(url, headers=headers, params=querystring)
        if response.status_code == 200:
            decoded = json.loads(response.text)
            display_results(decoded)
        else:
            print(f"[!] API Error. Status Code: {response.status_code}")
    except Exception as e:
        print(f"[!] Connection failed: {e}")

def display_results(data_dict):
    intel = data_dict['data']
    print("\n" + "="*40)
    print("        THREAT INTEL REPORT")
    print("="*40)
    print(f"Target IP:            {intel['ipAddress']}")
    print(f"Country of Origin:    {intel['countryCode']}")
    print(f"Abuse Malicious Score: {intel['abuseConfidenceScore']}%")
    print(f"Total System Reports: {intel['totalReports']}")
    print(f"Usage Infrastructure: {intel['usageType']}")
    print("="*40 + "\n")

if __name__ == "__main__":
    # Test with a known malicious IP simulation (e.g., standard hosting provider node)
    test_ip = "118.25.6.32"
    check_ip_reputation(test_ip)