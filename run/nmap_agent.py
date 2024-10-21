import subprocess
import xml.etree.ElementTree as ET
import json
import os
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional

# Configure logging using a single logger
logger = logging.getLogger("NmapScanner")
logger.setLevel(logging.DEBUG)
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
logger.addHandler(handler)

def run_nmap_script(ip_address: str, port: int, script_name: str, xml_output_file: str) -> Optional[str]:
    """
    Executes the Nmap script against the specified IP address and port.

    Args:
        ip_address (str): Target IP address.
        port (int): Target port.
        script_name (str): Name of the Nmap script.
        xml_output_file (str): Path to the output XML file.

    Returns:
        Optional[str]: Path to the XML output file if successful, None otherwise.
    """
    script_path = f'../scripts/{script_name}'

    if not os.path.exists(script_path):
        logger.error(f"Nmap script '{script_name}' not found in the 'scripts/' directory.")
        return None

    command = ['nmap', '--script', script_path, '-p', str(port), ip_address, '-oX', xml_output_file]
    logger.info(f"Running command: {' '.join(command)}")

    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        logger.info(f"Nmap scan completed. Output saved to {xml_output_file}")
        return xml_output_file
    except subprocess.CalledProcessError as e:
        logger.error(f"Nmap command failed: {e.stderr}")
        return None

def parse_nmap_xml_file(xml_file: str) -> List[Dict[str, Any]]:
    """
    Parses the Nmap XML file to extract scan results.

    Args:
        xml_file (str): Path to the XML file.

    Returns:
        List[Dict[str, Any]]: Parsed results from the XML file.
    """
    if not os.path.exists(xml_file) or os.path.getsize(xml_file) == 0:
        logger.error(f"XML output file '{xml_file}' does not exist or is empty.")
        return []

    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
        hosts = root.findall('host')
        if not hosts:
            logger.info(f"No results found in the XML file '{xml_file}'. The target may not have the required services.")
            return []

        return [parse_host(host) for host in hosts]
    except ET.ParseError as e:
        logger.error(f"Failed to parse XML file '{xml_file}': {e}")
        return []

def save_results_to_json(results: List[Dict[str, Any]], filename: str) -> None:
    """
    Saves scan results to a JSON file.

    Args:
        results (List[Dict[str, Any]]): Parsed results to save.
        filename (str): Path to the JSON output file.
    """
    with open(filename, 'w') as json_file:
        json.dump(results, json_file, indent=4)
    logger.info(f"Results saved to {filename}")

def parse_host(host: ET.Element) -> Dict[str, Any]:
    """
    Parses a host element from the Nmap XML output.

    Args:
        host (ET.Element): XML element representing a host.

    Returns:
        Dict[str, Any]: Parsed host information.
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
    """
    Retrieves text from an XML element.

    Args:
        element (ET.Element): The XML element.
        xpath (str): XPath to the desired element.
        attribute (str): Attribute to extract.
        default (Optional[str]): Default value if not found.

    Returns:
        Optional[str]: The extracted text or the default value.
    """
    node = element.find(xpath)
    return node.get(attribute) if node is not None else default

def parse_hostnames(host: ET.Element) -> List[str]:
    """
    Extracts hostnames from a host element.

    Args:
        host (ET.Element): The host XML element.

    Returns:
        List[str]: List of hostnames.
    """
    hostnames = host.find('hostnames')
    return [hostname.get('name') for hostname in hostnames.findall('hostname')] if hostnames else []

def parse_ports(host: ET.Element) -> List[Dict[str, Any]]:
    """
    Extracts port information from a host element.

    Args:
        host (ET.Element): The host XML element.

    Returns:
        List[Dict[str, Any]]: List of port details.
    """
    ports = host.find('ports')
    return [parse_port(port) for port in ports.findall('port')] if ports else []

def parse_port(port: ET.Element) -> Dict[str, Any]:
    """
    Extracts information from a port element.

    Args:
        port (ET.Element): The port XML element.

    Returns:
        Dict[str, Any]: Parsed port information.
    """
    return {
        'port_id': port.get('portid'),
        'protocol': port.get('protocol'),
        'state': get_xml_text(port, 'state', 'state', 'unknown'),
        'service': get_xml_text(port, 'service', 'name', 'N/A')
    }

def extract_additional_info(host: ET.Element) -> Dict[str, Any]:
    """
    Extracts additional information such as hardware details from a host element.

    Args:
        host (ET.Element): The host XML element.

    Returns:
        Dict[str, Any]: Additional details extracted from the host.
    """
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
    """
    Extracts a specific field from the host NSE script output.

    Args:
        host (ET.Element): The host XML element.
        field_name (str): The name of the field to extract.

    Returns:
        str: The extracted value or 'N/A' if not found.
    """
    for elem in host.findall(".//elem[@key]"):
        if elem.get('key') == field_name:
            return elem.text or 'N/A'
    return 'N/A'
