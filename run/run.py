import time
import json
import logging
import os
from datetime import datetime
from nmap_agent import run_nmap_script, parse_nmap_xml_file, save_results_to_json, cleanup_old_xml_files

# Configure logging
logger = logging.getLogger("NmapScanner")
logger.setLevel(logging.DEBUG)
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
logger.addHandler(handler)

# Get the current working directory for relative path handling
base_dir = os.getcwd()

def load_config(config_path: str) -> dict:
    """
    Loads configuration from a JSON file.
    """
    with open(config_path, 'r') as config_file:
        return json.load(config_file)

def ensure_results_directory() -> str:
    """
    Ensures that the results directory exists.
    """
    results_dir = os.path.join(base_dir, 'results')
    os.makedirs(results_dir, exist_ok=True)
    return results_dir

def execute_scan(ip: str, target_port: int, script_name: str, results_dir: str) -> dict:
    """
    Executes a scan for a given IP, port, and script, and parses the results.
    """
    xml_output_file = os.path.join(results_dir, f'{ip}_{script_name}.xml')
    logger.info(f"Scanning IP: {ip}, Port: {target_port}, Script: {script_name}")
    try:
        xml_file = run_nmap_script(ip, target_port, script_name, xml_output_file)
        if xml_file:
            parsed_results = parse_nmap_xml_file(xml_file)
            return {
                "target_ip": ip,
                "target_port": target_port,
                "script_name": script_name,
                "results": parsed_results
            }
        else:
            logger.error(f"Scan failed for IP: {ip}, Script: {script_name}")
    except Exception as e:
        logger.error(f"Error during scan for IP {ip}, Script {script_name}: {e}")
    return None

def perform_all_scans(scans: list, results_dir: str) -> list:
    """
    Iterates over all scans and executes them.
    """
    all_results = []
    successful_scans = 0
    failed_scans = 0

    for scan in scans:
        ip_list = scan['target_ip']
        target_port = scan['target_port']
        script_names = scan['script_name']

        for ip in ip_list:
            for script_name in script_names:
                result = execute_scan(ip, target_port, script_name, results_dir)
                if result:
                    all_results.append(result)
                    successful_scans += 1
                else:
                    failed_scans += 1

    logger.info(f"Scan cycle completed: {successful_scans} successful scans, {failed_scans} failed scans.")
    return all_results

def save_scan_results(config: dict, all_results: list, results_dir: str) -> None:
    """
    Saves all scan results to a JSON file.
    """
    # Replace colons in the timestamp to make it filename-safe for Windows
    current_time = datetime.now().isoformat().replace(":", "_")
    json_output_file = os.path.join(results_dir, f'scan_results_{current_time}.json')
    save_results_to_json(config, all_results, json_output_file)
    logger.info(f"All scan results saved to {json_output_file}")

    # Clean up old XML files, keeping only the latest 3
    cleanup_old_xml_files(results_dir, keep_count=3)

def start_scan_loop(config: dict) -> None:
    """
    Manages the scan loop based on the provided configuration.
    """
    wait_time_minutes = config['wait_time_minutes']
    scans = config['scans']
    results_dir = ensure_results_directory()

    while True:
        logger.info("Starting scans based on configuration.")
        all_results = perform_all_scans(scans, results_dir)
        save_scan_results(config, all_results, results_dir)
        logger.info(f"Waiting for {wait_time_minutes} minutes before the next scan...")
        time.sleep(wait_time_minutes * 60)

if __name__ == "__main__":
    # Load configuration from config.json
    config_file_path = os.path.join(base_dir, 'config.json')
    config = load_config(config_file_path)
    start_scan_loop(config)
