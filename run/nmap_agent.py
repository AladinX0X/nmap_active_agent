import subprocess
import xml.etree.ElementTree as ET
import json
import os
import glob
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional

# Configure logging using a single logger
logger = logging.getLogger("NmapScanner")
logger.setLevel(logging.DEBUG)
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
logger.addHandler(handler)

base_dir = os.getcwd()

def run_nmap_script(ip_address: str, port: int, script_name: str, xml_output_file: str) -> Optional[str]:
    """
    Executes the Nmap script against the specified IP address and port.
    """
    try:
        if not ip_address or not script_name:
            raise ValueError("IP address or script name is not specified.")
        
        # Construct the path to the script using os.path.join for better compatibility
        script_path = os.path.join(base_dir, 'scripts', script_name)
        if not os.path.exists(script_path):
            raise FileNotFoundError(f"Nmap script '{script_name}' not found in the 'scripts/' directory at path: {script_path}.")
        
        # Construct the output path using os.path.join
        xml_output_path = os.path.join(base_dir, xml_output_file)
        command = ['nmap', '--script', script_path, '-p', str(port), ip_address, '-oX', xml_output_path]
        logger.info(f"Running command: {' '.join(command)}")

        result = subprocess.run(command, capture_output=True, text=True, check=True)
        logger.info(f"Nmap scan completed. Output saved to {xml_output_path}")
        return xml_output_path

    except ValueError as ve:
        logger.error(f"Input error: {ve}")
    except FileNotFoundError as fe:
        logger.error(fe)
    except subprocess.CalledProcessError as e:
        logger.error(f"Nmap command failed: {e.stderr}")
    except Exception as e:
        logger.error(f"Unexpected error during scan: {e}")
    return None

def parse_nmap_xml_file(xml_file: str) -> List[Dict[str, Any]]:
    """
    Parses the Nmap XML file to extract scan results.
    """
    try:
        xml_file_path = os.path.join(base_dir, xml_file)
        if not os.path.exists(xml_file_path) or os.path.getsize(xml_file_path) == 0:
            logger.error(f"XML output file '{xml_file_path}' does not exist or is empty.")
            return []

        tree = ET.parse(xml_file_path)
        root = tree.getroot()
        hosts = root.findall('host')
        if not hosts:
            logger.info(f"No results found in the XML file '{xml_file_path}'. The target may not have the required services.")
            return []

        return [parse_host(host) for host in hosts]
    except ET.ParseError as e:
        logger.error(f"Failed to parse XML file '{xml_file}': {e}")
    except Exception as e:
        logger.error(f"Unexpected error during XML parsing: {e}")
    return []

def save_results_to_json(config: dict, results: List[Dict[str, Any]], filename: str) -> None:
    """
    Saves scan results to a JSON file in the specified format.
    """
    output_data = {
        "wait_time_minutes": config['wait_time_minutes'],
        "scans": results
    }
    json_file_path = os.path.join(base_dir, filename)
    try:
        with open(json_file_path, 'w') as json_file:
            json.dump(output_data, json_file, indent=4)
        logger.info(f"Results saved to {json_file_path}")
    except IOError as e:
        logger.error(f"Failed to write results to {json_file_path}: {e}")

def parse_host(host: ET.Element) -> Dict[str, Any]:
    """
    Parses a host element from the Nmap XML output.
    """
    result = {
        'ip_address': get_xml_text(host, "address[@addrtype='ipv4']", 'addr'),
        'mac_address': get_xml_text(host, "address[@addrtype='mac']", 'addr', 'N/A'),
        'vendor': get_xml_text(host, "address[@addrtype='mac']", 'vendor', 'N/A'),
        'hostnames': parse_hostnames(host),
        'ports': parse_ports(host),
    }

    # Extract additional information based on NSE script output or XML structure
    result.update(extract_additional_info(host))
    return result

def get_xml_text(element: ET.Element, xpath: str, attribute: str, default: Optional[str] = None) -> Optional[str]:
    node = element.find(xpath)
    return node.get(attribute) if node is not None else default

def parse_hostnames(host: ET.Element) -> List[str]:
    hostnames = host.find('hostnames')
    return [hostname.get('name') for hostname in hostnames.findall('hostname')] if hostnames else []

def parse_ports(host: ET.Element) -> List[Dict[str, Any]]:
    ports = host.find('ports')
    return [parse_port(port) for port in ports.findall('port')] if ports else []

def parse_port(port: ET.Element) -> Dict[str, Any]:
    return {
        'port_id': port.get('portid'),
        'protocol': port.get('protocol'),
        'state': get_xml_text(port, 'state', 'state', 'unknown'),
        'service': get_xml_text(port, 'service', 'name', 'N/A')
    }

def extract_additional_info(host: ET.Element) -> Dict[str, Any]:
    additional_info = {
        "Module": extract_nse_field(host, "Module"),
        "Basic Hardware": extract_nse_field(host, "Basic Hardware"),
        "Version": extract_nse_field(host, "Version"),
        "System Name": extract_nse_field(host, "System Name"),
        "Module Type": extract_nse_field(host, "Module Type"),
        "Serial Number": extract_nse_field(host, "Serial Number"),
        "Plant Identification": extract_nse_field(host, "Plant Identification"),
        "Copyright": extract_nse_field(host, "Copyright")
    }
    return additional_info

def extract_nse_field(host: ET.Element, field_name: str) -> str:
    for elem in host.findall(".//elem[@key]"):
        if elem.get('key') == field_name:
            return elem.text or 'N/A'
    return 'N/A'

def cleanup_old_xml_files(results_dir: str, keep_count: int = 3) -> None:
    """
    Deletes XML files from the results directory, keeping only the latest 'keep_count' files.
    """
    # Get a list of all XML files in the results directory sorted by modification time (oldest first)
    xml_files = sorted(
        glob.glob(os.path.join(results_dir, "*.xml")),
        key=os.path.getmtime
    )

    # Calculate the number of files to delete
    files_to_delete = len(xml_files) - keep_count

    # If there are more XML files than 'keep_count', delete the oldest ones
    if files_to_delete > 0:
        for xml_file in xml_files[:files_to_delete]:
            try:
                os.remove(xml_file)
                logger.info(f"Deleted old XML file: {xml_file}")
            except Exception as e:
                logger.error(f"Failed to delete XML file {xml_file}: {e}")
