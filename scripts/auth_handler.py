import argparse
import base64
import hashlib
import json
import os
import secrets
import sys
import webbrowser
import requests
import logging
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Constants for environment file token management
ENV_FILE = ".env"
TOKEN_KEY = "SESSION_ID_TOKEN"

def get_token_from_env():
    """
    Safely parse the .env file in the current working directory to look 
    for the saved session ID token.
    """
    try:
        if not os.path.exists(ENV_FILE):
            return None
            
        with open(ENV_FILE, "r") as f:
            for line in f:
                line = line.strip()
                # Find the token key, ignoring potential comments or empty lines
                if line.startswith(f"{TOKEN_KEY}="):
                    # Extract the value, stripping out the key and any quotes
                    return line.split("=", 1)[1].strip().strip('"\'')
    except Exception as e:
        logger.error(f"Error reading {ENV_FILE} file: {e}")
        
    return None

def store_token_in_env(token):
    """
    Safely update ONLY the specific session ID line inside the .env file 
    with the newly generated token. Preserves all other variables.
    """
    lines = []
    token_found = False
    
    try:
        # Read existing lines if the file exists
        if os.path.exists(ENV_FILE):
            with open(ENV_FILE, "r") as f:
                lines = f.readlines()
        
        # Write back to the file
        with open(ENV_FILE, "w") as f:
            for line in lines:
                if line.strip().startswith(f"{TOKEN_KEY}="):
                    # Overwrite only the matching token line
                    f.write(f"{TOKEN_KEY}={token}\n")
                    token_found = True
                else:
                    # Keep all other environment variables intact
                    f.write(line)
            
            # If the token key wasn't in the file, append it
            if not token_found:
                if lines and not lines[-1].endswith("\n"):
                    f.write("\n") # Ensure we start on a new line
                f.write(f"{TOKEN_KEY}={token}\n")
                
    except Exception as e:
        logger.error(f"Error safely updating {ENV_FILE} file: {e}")

def validate_session_token(vault_url, token):
    """
    Verify the token using the Veeva Vault 'Validate Session User' endpoint via v25.3 API.
    Returns True if valid, False if invalid/expired.
    """
    url = f"{vault_url.rstrip('/')}/api/v25.3/objects/users/me"
    headers = {
        "Authorization": token,
        "Accept": "application/json"
    }
    
    try:
        response = requests.get(url, headers=headers)
        data = response.json()
        
        if response.status_code == 200 and data.get("responseStatus") == "SUCCESS":
            # Extract user info to confirm active token
            users = data.get("users", [])
            user_info = users[0].get("user", {}) if users else data.get("user", {})
            user_name = user_info.get("user_name", "Unknown User")
            
            logger.info(f"Token is active. Authenticated as: {user_name}")
            return True
            
        else:
            # Check for specific expiration error
            errors = data.get("errors", [])
            for error in errors:
                if error.get("type") == "INVALID_SESSION_ID":
                    logger.info("Session token expired (INVALID_SESSION_ID). Re-authenticating...")
                    return False
                    
            logger.warning(f"Token validation failed unexpectedly: {data}")
            return False
            
    except Exception as e:
        logger.error(f"Error during token validation request: {e}")
        return False

# PKCE Helper Functions
def generate_code_verifier():
    return secrets.token_urlsafe(64)

def generate_code_challenge(verifier):
    m = hashlib.sha256()
    m.update(verifier.encode("ascii"))
    return base64.urlsafe_b64encode(m.digest()).decode("ascii").replace("=", "")

def discover_auth(vault_url, username):
    """
    Call the /auth/discovery endpoint to find the oauth_oidc_profile_id and idp_url.
    """
    try:
        discovery_url = f"{vault_url.rstrip('/')}/api/v25.3/auth/discovery"
        params = {"username": username}
        response = requests.get(discovery_url, params=params)
        if response.status_code == 200:
            data = response.json()
            if data.get("responseStatus") == "SUCCESS":
                for profile in data.get("data", []):
                    if profile.get("authType") == "OAUTH":
                        return profile
    except Exception as e:
        logger.error(f"Discovery error: {e}")
    return None

def exchange_code(token_url, code, client_id, redirect_uri, code_verifier):
    """
    Exchange the authorization code for an access token at the IdP.
    """
    data = {
        "grant_type": "authorization_code",
        "client_id": client_id,
        "code": code,
        "redirect_uri": redirect_uri,
        "code_verifier": code_verifier
    }
    try:
        response = requests.post(token_url, data=data)
        if response.status_code == 200:
            return response.json().get("access_token")
        else:
            logger.error(f"Code exchange failed: {response.status_code} {response.text}")
    except Exception as e:
        logger.error(f"Code exchange error: {e}")
    return None

def get_vault_session(vault_url, profile_id, access_token, vault_dns=None, client_id=None):
    """
    Exchange the OAuth access token for a Vault session token.
    Uses the global login.veevavault.com endpoint.
    """
    url = f"https://login.veevavault.com/auth/oauth/session/{profile_id}"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json"
    }
    data = {}
    if vault_dns:
        data["vaultDNS"] = vault_dns
    if client_id:
        data["client_id"] = client_id
        
    try:
        response = requests.post(url, headers=headers, data=data)
        if response.status_code == 200:
            data = response.json()
            if data.get("responseStatus") == "SUCCESS":
                return data.get("sessionId")
            else:
                logger.error(f"Vault session error: {data.get('errors')}")
        else:
            logger.error(f"Vault session request failed: {response.status_code} {response.text}")
    except Exception as e:
        logger.error(f"Vault session exchange error: {e}")
    return None

class RedirectHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html><body><h1>Authentication Successful</h1><p>You can close this window now.</p></body></html>")
        
        query = urlparse(self.path).query
        params = parse_qs(query)
        if "code" in params:
            self.server.authorization_code = params["code"][0]
            
    # Suppress default logging to keep console clean
    def log_message(self, format, *args):
        pass

def authenticate(vault_url, username=None):
    """
    Performs authentication and returns a session token.
    Uses cached token if valid, otherwise performs OAuth flow.
    """
    # Load defaults from assets/defaults.json
    script_dir = os.path.dirname(os.path.abspath(__file__))
    defaults_path = os.path.join(script_dir, "..","assets", "defaults.json")
    defaults = {}
    try:
        if os.path.exists(defaults_path):
            with open(defaults_path, "r") as f:
                defaults = json.load(f)
    except Exception as e:
        logger.error(f"Error loading defaults: {e}")
        
    client_id = defaults.get("VAULT_OAUTH_CLIENT_ID", "vault-analyzer-skill")
    redirect_uri = defaults.get("VAULT_OAUTH_REDIRECT_URI", "http://localhost:8000")
    idp_url = defaults.get("VAULT_OAUTH_IDP_URL")
    profile_id = defaults.get("VAULT_OIDC_PROFILE_ID")
    
    # --- Token Validation Flow ---
    token = get_token_from_env()
    if token:
        logger.info("Existing token found in .env file. Validating...")
        if validate_session_token(vault_url, token):
            return token
    # -----------------------------
    
    # Discovery step (If no token or token is expired)
    if username and not profile_id:
        logger.info(f"Discovering auth profile for {username}...")
        profile = discover_auth(vault_url, username)
        if profile:
            profile_id = profile.get("oauth_oidc_profile_id")
            idp_url = profile.get("idp_url", idp_url)
            logger.info(f"Discovered Profile ID: {profile_id}")
        else:
            logger.error("Discovery failed to find an OAUTH profile.")
    
    # Extract port from redirect_uri
    parsed_redirect = urlparse(redirect_uri)
    port = parsed_redirect.port or 80
    
    # Start PKCE flow
    code_verifier = generate_code_verifier()
    code_challenge = generate_code_challenge(code_verifier)
    state = secrets.token_urlsafe(16)
    
    # Start ephemeral server
    try:
        server = HTTPServer(("localhost", port), RedirectHandler)
    except Exception as e:
        logger.error(f"Error starting server on port {port}: {e}")
        return None
        
    server.authorization_code = None
    
    # Construct Authorization URL
    if idp_url:
        auth_base = idp_url.rstrip("/")
        if not auth_base.endswith("/authorize"):
            auth_base = f"{auth_base}/authorize"
        auth_url = auth_base
    else:
        auth_url = f"{vault_url.rstrip('/')}/api/v25.3/auth/oauth/authorize"
    
    full_auth_url = (
        f"{auth_url}?response_type=code&client_id={client_id}&"
        f"redirect_uri={redirect_uri}&code_challenge={code_challenge}&"
        f"code_challenge_method=S256&scope=openid profile email&state={state}"
    )
    
    logger.info(f"Initiating secure login. If the browser does not open, navigate to:\n{full_auth_url}")
    
    webbrowser.open_new(full_auth_url)
    
    try:
        server.handle_request()
    except KeyboardInterrupt:
        logger.info("\nAuthentication cancelled.")
        return None
    
    if not server.authorization_code:
        logger.error("Failed to capture authorization code.")
        return None

    # Exchange code for access token
    if not idp_url:
        logger.error("Missing IdP URL for token exchange.")
        return None
        
    token_url = idp_url.rstrip("/")
    if not token_url.endswith("/token"):
        token_url = f"{token_url}/token"
        
    access_token = exchange_code(token_url, server.authorization_code, client_id, redirect_uri, code_verifier)
    if not access_token:
        return None
        
    # Exchange access token for Vault session
    if not profile_id:
        logger.error("Missing Profile ID for session exchange.")
        return None
        
    parsed_vault = urlparse(vault_url)
    vault_dns = parsed_vault.netloc
    
    token = get_vault_session(vault_url, profile_id, access_token, vault_dns=vault_dns, client_id=client_id)
    if not token:
        return None
        
    # Save the new token safely to the .env file
    store_token_in_env(token)
    
    server.server_close()
    return token

def main():
    parser = argparse.ArgumentParser(description="Veeva Vault Authentication Handler.")
    parser.add_argument("--vault-url", required=True, help="Veeva Vault base URL.")
    parser.add_argument("--username", help="Veeva Vault username for discovery.")
    
    args = parser.parse_args()
    
    token = authenticate(args.vault_url, args.username)
    if token:
        print(token)
    else:
        sys.exit(1)

if __name__ == "__main__":
    main()

if __name__ == "__main__":
    main()