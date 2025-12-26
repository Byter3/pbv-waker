import logging
from ldap3 import Server, Connection, ALL, SUBTREE, SIMPLE
import json
import os

# Configuration from ad_config.json
def load_ad_config():
    config_path = os.path.join(os.path.dirname(__file__), 'ad_config.json')
    if not os.path.exists(config_path):
        print("Error: ad_config.json not found.")
        return {}
    with open(config_path, 'r') as f:
        return json.load(f)

config = load_ad_config()

AD_SERVER_IP = config.get('AD_SERVER_IP', '127.0.0.1')
AD_SERVER_PORT = config.get('AD_SERVER_PORT', 389)
AD_BIND_DN = config.get('AD_BIND_DN', '')
AD_BIND_PASSWORD = config.get('AD_BIND_PASSWORD', '')
AD_SEARCH_BASE = config.get('AD_SEARCH_BASE', '')

def get_admin_connection():
    """Establishes a connection to AD using the Service Account."""
    try:
        server = Server(AD_SERVER_IP, port=AD_SERVER_PORT, get_info=ALL)
        conn = Connection(server, user=AD_BIND_DN, password=AD_BIND_PASSWORD, authentication=SIMPLE)
        if not conn.bind():
            print(f"AD Bind Failed: {conn.result}")
            return None
        return conn
    except Exception as e:
        print(f"AD Connection Error: {e}")
        return None

def authenticate_user(username, password):
    """
    Authenticates a user against Active Directory.
    1. Binds with Service Account to find the user's DN.
    2. Binds with the User's DN and password to verify credentials.
    """
    if not username or not password:
        return False

    conn = get_admin_connection()
    if not conn:
        return False
    
    try:
        # Search for the user's DN
        search_filter = f'(sAMAccountName={username})'
        conn.search(AD_SEARCH_BASE, search_filter, attributes=['distinguishedName'])
        
        if not conn.entries:
            print(f"User {username} not found in AD.")
            return False
        
        user_dn = conn.entries[0].distinguishedName.value
        
        # Verify credentials by binding as the user
        server = Server(AD_SERVER_IP, port=AD_SERVER_PORT, get_info=ALL)
        user_conn = Connection(server, user=user_dn, password=password, authentication=SIMPLE)
        if user_conn.bind():
            user_conn.unbind()
            return True
        else:
            print(f"Authentication failed for {username}: {user_conn.result}")
            return False
            
    except Exception as e:
        print(f"Authentication Error: {e}")
        return False
    finally:
        conn.unbind()

def sync_users_from_ad(current_users=None):
    """
    Queries AD for all users.
    Returns: {username: {'email': email}}
    """
    conn = get_admin_connection()
    if not conn:
        return {}
    
    synced_users = {}
    try:
        # Search for all users
        search_filter = '(objectClass=person)'
        conn.search(AD_SEARCH_BASE, search_filter, attributes=['sAMAccountName', 'mail'])
        
        allowed_domains = ['@gmail.com', '@postboxvisual.com', '@fridaymails.com']

        for entry in conn.entries:
            # Handle cases where attributes might be missing or list-like
            username = str(entry.sAMAccountName).strip() if entry.sAMAccountName else None
            if not username:
                continue
                
            email = str(entry.mail).strip() if entry.mail else None
            
            # Filter by allowed domains
            if not email or not any(email.lower().endswith(domain) for domain in allowed_domains):
                continue
            
            synced_users[username] = {
                'email': email
            }
            
    except Exception as e:
        print(f"AD Sync failed: {e}")
    finally:
        conn.unbind()
        
    return synced_users
