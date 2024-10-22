import time
import json
import logging
from datetime import datetime
from nmap_agent import run_nmap_script, parse_nmap_xml_file, save_results_to_json

# Configure logging
logger = logging.getLogger("NmapScanner")
logger.setLevel(logging.DEBUG)
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
logger.addHandler(handler)

def load_config(config_path: str) -> dict:
    """
    Loads configuration from a JSON file.

    Args:
        config_path (str): Path to the configuration file.

    Returns:
        dict: Configuration parameters.
    """
    with open(config_path, 'r') as config_file:
        return json.load(config_file)

def start_scan_loop(config: dict) -> None:
    """
    Starts the continuous scanning loop based on the provided configuration.

    Args:
        config (dict): Configuration parameters for the scan.
    """
    target_ip = config['target_ip']
    target_port = config['target_port']
    script_name = config['script_name']
    wait_time_minutes = config['wait_time_minutes']

    while True:
        # Generate filenames for XML and JSON results
        current_time = datetime.now().isoformat()
        xml_output_file = f'results/scan_results_{script_name}.xml'
        json_output_file = f'results/scan_results_{current_time}.json'

        logger.info(f"Starting scan for IP: {target_ip}, Port: {target_port}, Script: {script_name}")
        
        # Run the Nmap scan and parse the results
        xml_file = run_nmap_script(target_ip, target_port, script_name, xml_output_file)
        
        if xml_file:
            scan_results = parse_nmap_xml_file(xml_file)
            if scan_results:
                save_results_to_json(scan_results, json_output_file)
                logger.info(f"Results saved to {json_output_file}")
            else:
                logger.info(f"No results found in the XML file '{xml_file}'.")
        else:
            logger.error("Failed to run the Nmap scan.")

        logger.info(f"Waiting for {wait_time_minutes} minutes before the next scan...")
        time.sleep(wait_time_minutes * 60)

if __name__ == "__main__":
    # Load configuration from config.json
    config = load_config('config.json')
    start_scan_loop(config)
