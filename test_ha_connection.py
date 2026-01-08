import json
import requests
import os

def load_json(file_path):
    if os.path.exists(file_path):
        with open(file_path, 'r', encoding='utf-8') as file:
            return json.load(file)
    return {}

def test_connection():
    config = load_json('ha_config.json')
    base_url = config.get('url')
    token = config.get('token')
    
    if not base_url or not token:
        print("FAIL: Missing URL or Token in ha_config.json")
        return

    print(f"Testing connection to: {base_url}")
    
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    
    try:
        # Check API status
        resp = requests.get(f"{base_url}/api/", headers=headers, timeout=5)
        print(f"Status Code: {resp.status_code}")
        print(f"Response: {resp.text}")
        
        if resp.status_code == 200:
            print("SUCCESS: Connection established and authenticated.")
        elif resp.status_code == 401:
            print("FAIL: Authentication failed (401). Check your Token.")
        else:
            print("FAIL: Unexpected status code.")
            
    except Exception as e:
        print(f"FAIL: Network error: {e}")

if __name__ == "__main__":
    test_connection()
