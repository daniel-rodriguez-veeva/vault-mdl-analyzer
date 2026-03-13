import argparse
import logging
import os
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
import auth_handler
from vault_client import VaultClient

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def sanitize_directory_name(vault_url):
    """Sanitize the vault_url to create a safe root directory name."""
    parsed = urlparse(vault_url)
    name = parsed.netloc.split('.')[0]
    # Further sanitize if needed
    name = re.sub(r'[^a-zA-Z0-9_]', '_', name)
    return name

def sanitize_filename(name):
    """Sanitize component name for file system safety."""
    return re.sub(r'[\\/*?:"<>|]', '_', name)

class FlowController:
    def __init__(self, vault_url, username=None, target=None, force=False, path=None):
        self.vault_url = vault_url
        self.username = username
        self.target = target
        self.force = force
        self.vault_name = sanitize_directory_name(vault_url)
        
        self.base_dir = os.path.join(path, self.vault_name) if path else self.vault_name

        os.makedirs(self.base_dir, exist_ok=True)
        
        self.client = None

    def authenticate(self):
        token = auth_handler.authenticate(self.vault_url, self.username)
        if not token:
            logger.error("Authentication failed.")
            return False
        self.client = VaultClient(self.vault_url, token, self.username)
        return True

    def extract_mdl(self, component):
        comp_type = component.get("component_type__v")
        comp_name = component.get("component_name__v")
        comp_label = component.get("label__v", comp_name)
        
        if not comp_type or not comp_name:
            return False, "Missing component type or name"

        sanitized_label = sanitize_filename(comp_label)
        type_dir = os.path.join(self.base_dir, comp_type)
        os.makedirs(type_dir, exist_ok=True)
        
        file_path = os.path.join(type_dir, f"{sanitized_label}.MDL")
        
        # Idempotency check
        if os.path.exists(file_path) and not self.force:
            logger.info(f"Skipped (Exists): {comp_type}.{comp_name}")
            return True, "Already exists"

        try:
            mdl_content = self.client.get_mdl(f"{comp_type}.{comp_name}")
            if mdl_content:
                with open(file_path, "w") as f:
                    f.write(mdl_content)
                logger.info(f"Extracted: {comp_type}.{comp_name}")
                return True, "Success"
            else:
                return False, "Failed to retrieve MDL content"
        except Exception as e:
            return False, str(e)

    def run_targeted_mode(self):
        sanitized_target = self.target.replace("'", "''")
        query = f"SELECT label__v, component_name__v, component_type__v FROM vault_component__v WHERE component_name__v = '{sanitized_target}' OR label__v = '{sanitized_target}'"
        
        logger.info(f"Searching for target component: {self.target}")
        result = self.client.execute_query(query)
        
        if not result or result.get("responseStatus") != "SUCCESS":
            logger.error(f"Error querying for target {self.target}: {result}")
            return

        data = result.get("data", [])
        if not data:
            logger.warning(f"No matches found for target: {self.target}")
            return

        logger.info(f"Found {len(data)} matching components. Starting extraction...")
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {executor.submit(self.extract_mdl, comp): comp for comp in data}
            for future in as_completed(futures):
                comp = futures[future]
                try:
                    success, message = future.result()
                    if not success:
                        logger.error(f"Failed to extract MDL for {comp.get('component_name__v')}: {message}")
                except Exception as e:
                    logger.error(f"Exception during extraction for {comp.get('component_name__v')}: {e}")

    def run(self):
        if not self.authenticate():
            return
        
        self.run_targeted_mode()

def main():
    parser = argparse.ArgumentParser(description="Veeva Vault Metadata Extraction Flow Controller.")
    parser.add_argument("--vault-url", required=True, help="Veeva Vault base URL.")
    parser.add_argument("--username", help="Veeva Vault username.")
    parser.add_argument("--target", required=True, help="Technical name or label of a specific component to extract.")
    parser.add_argument("--path", help="The root directory where the extracted MDL data should be stored.")
    parser.add_argument("--force", action="store_true", help="Overwrite existing MDL files.")
    parser.add_argument("--clear-token", action="store_true", help="Remove the SESSION_ID_TOKEN from .env before starting.")
    
    args = parser.parse_args()
    
    if args.clear_token:
        if os.path.exists(".env"):
            lines = []
            with open(".env", "r") as f:
                lines = f.readlines()
            with open(".env", "w") as f:
                for line in lines:
                    if not line.strip().startswith("SESSION_ID_TOKEN="):
                        f.write(line)
            logger.info("Cleared SESSION_ID_TOKEN from .env")

    controller = FlowController(args.vault_url, args.username, target=args.target, force=args.force, path=args.path)
    controller.run()

if __name__ == "__main__":
    main()
