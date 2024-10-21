import time
import json
from nmap_agent import start_nmap_scan

def load_config(config_path):
    with open(config_path, 'r') as config_file:
        return json.load(config_file)

if __name__ == "__main__":
    # Load configuration from config.json
    config = load_config('config.json')

    # Extract parameters from the config
    target_ip = config['target_ip']
    target_port = config['target_port']
    script_name = config['script_name']
    wait_time_minutes = config['wait_time_minutes']

    # Loop to run the scan regularly
    while True:
        # Start the Nmap scan
        start_nmap_scan(target_ip, target_port, script_name)

        # Wait time before the next scan
        print(f"Waiting for {wait_time_minutes} minutes before the next scan...")
        time.sleep(wait_time_minutes * 60)
