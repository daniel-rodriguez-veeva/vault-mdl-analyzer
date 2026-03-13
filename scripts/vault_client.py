import argparse
import json
import requests
import sys
import os
import threading
import time
import random
import logging
from urllib.parse import urljoin
import auth_handler

# Configure logging
logger = logging.getLogger(__name__)

class VaultClient:
    def __init__(self, vault_url, session_token=None, username=None):
        self.vault_url = vault_url.rstrip("/")
        self.session_token = session_token
        self.username = username
        self.auth_lock = threading.RLock()
        self.is_authenticating = False
        self.max_retries = 5

    def _call_api(self, method, url, **kwargs):
        retry_count = 0
        while retry_count <= self.max_retries:
            headers = kwargs.get("headers", {})
            headers["Authorization"] = self.session_token
            headers["Accept"] = "application/json"
            kwargs["headers"] = headers

            try:
                response = requests.request(method, url, **kwargs)
                
                # Handle Success
                if response.status_code == 200:
                    return response

                # Handle Rate Limiting
                if response.status_code == 429:
                    wait_time = (2 ** retry_count) + random.uniform(0, 1)
                    logger.warning(f"Rate limited (429). Waiting {wait_time:.2f}s before retry {retry_count + 1}/{self.max_retries}")
                    time.sleep(wait_time)
                    retry_count += 1
                    continue

                # Handle Auth Refresh Coordination (401/403)
                if response.status_code in [401, 403]:
                    logger.info(f"Auth error ({response.status_code}). Attempting token refresh...")
                    with self.auth_lock:
                        # Double-check if another thread already refreshed the token
                        if not self.is_authenticating:
                            self.is_authenticating = True
                            try:
                                new_token = auth_handler.authenticate(self.vault_url, self.username)
                                if new_token:
                                    self.session_token = new_token
                                    logger.info("Token refreshed successfully.")
                                else:
                                    logger.error("Failed to refresh token.")
                                    return response
                            finally:
                                self.is_authenticating = False
                        
                    retry_count += 1
                    continue

                # Handle Transient Errors
                if response.status_code in [500, 502, 503, 504]:
                    wait_time = (2 ** retry_count) + random.uniform(0, 1)
                    logger.warning(f"Transient error ({response.status_code}). Waiting {wait_time:.2f}s before retry {retry_count + 1}/{self.max_retries}")
                    time.sleep(wait_time)
                    retry_count += 1
                    continue

                # For other errors, return the response
                return response

            except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
                wait_time = (2 ** retry_count) + random.uniform(0, 1)
                logger.warning(f"Network error ({type(e).__name__}). Waiting {wait_time:.2f}s before retry {retry_count + 1}/{self.max_retries}")
                time.sleep(wait_time)
                retry_count += 1
                continue
            except Exception as e:
                logger.error(f"Unexpected error during API call: {e}")
                raise

        return None

    def execute_query(self, query_or_url):
        """Handles both initial VQL and next_page relative/absolute URLs."""
        if query_or_url.startswith("http"):
            url = query_or_url
            method = "GET"
            params = {}
            data = {}
        elif query_or_url.startswith("/api"):
            url = f"{self.vault_url}{query_or_url}"
            method = "GET"
            params = {}
            data = {}
        else:
            # Initial VQL query
            url = f"{self.vault_url}/api/v25.3/query"
            method = "POST"
            params = {}
            data = {"q": query_or_url}
            
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        response = self._call_api(method, url, data=data, params=params, headers=headers)
        return response.json() if response else None

    def get_component_types(self):
        """Fetches available component types."""
        url = f"{self.vault_url}/api/v25.3/metadata/components"
        response = self._call_api("GET", url)
        return response.json() if response else None

    def get_mdl(self, component_path):
        """Fetches MDL as raw text. component_path should be component_type.component_name"""
        url = f"{self.vault_url}/api/mdl/components/{component_path}"
        response = self._call_api("GET", url)
        if response and response.status_code == 200:
            return response.text
        return None

def main():
    parser = argparse.ArgumentParser(description="Veeva Vault API interactions.")
    parser.add_argument("--token", help="Veeva Vault session token.")
    parser.add_argument("--vault-url", required=True, help="Veeva Vault base URL (e.g. https://yourvault.veevavault.com).")
    parser.add_argument("--username", help="Veeva Vault username.")
    parser.add_argument("--action", required=True, choices=["metadata", "vql", "mdl"], help="The action to perform.")
    parser.add_argument("--payload", help="The payload for the request (JSON string or query string).")
    
    args = parser.parse_args()
    
    client = VaultClient(args.vault_url, args.token, args.username)
    
    try:
        if args.action == "metadata":
            result = client.get_component_types()
            print(json.dumps(result))
        elif args.action == "vql":
            result = client.execute_query(args.payload)
            print(json.dumps(result))
        elif args.action == "mdl":
            result = client.get_mdl(args.payload)
            if result:
                print(json.dumps({"responseStatus": "SUCCESS", "mdl": result}))
            else:
                print(json.dumps({"responseStatus": "FAILURE", "error": "Failed to retrieve MDL"}))
    except Exception as e:
        print(json.dumps({"responseStatus": "FAILURE", "error": str(e)}))
        sys.exit(1)

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()
