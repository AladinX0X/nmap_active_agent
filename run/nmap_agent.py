import subprocess
import xml.etree.ElementTree as ET
import json
import os
from datetime import datetime


class NmapScanner:
    def run_nmap_script(self, ip_address, port, script_name, xml_output_file):
        script_path = f'../scripts/{script_name}'
        
        if not os.path.exists(script_path):
            print(f"Error: Nmap script '{script_name}' not found in the 'scripts/' directory.")
            return
        
        # Execute the Nmap command using the script path
        command = f'nmap --script {script_path} -p {port} {ip_address} -oX {xml_output_file}'
        print(f"Running command: {command}")
        
        result = subprocess.run(command, shell=True, capture_output=True, text=True)

        if result.returncode != 0:
            print(f"Error: Nmap command failed with exit code {result.returncode}")
            print(result.stderr)
        else:
            print(f"Nmap scan completed. Output saved to {xml_output_file}")

    def parse_nmap_xml_file(self, xml_file):
        if not os.path.exists(xml_file) or os.path.getsize(xml_file) == 0:
            print(f"Error: XML output file '{xml_file}' does not exist or is empty.")
            return []

        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            hosts = root.findall('host')
            if not hosts:
                print(f"No results found in the XML file '{xml_file}'. The target may not have the required services.")
                return []
            
            return [self._parse_host(host) for host in hosts]
    
        except ET.ParseError as e:
            print(f"Error: Failed to parse XML file '{xml_file}'. The file may be corrupted.")
            print(e)
            return []

    def save_results_to_json(self, results, filename):
        with open(filename, 'w') as json_file:
            json.dump(results, json_file, indent=4)

    def _parse_host(self, host):
        result = {
            'ip_address': self._get_xml_text(host, "address[@addrtype='ipv4']", 'addr'),
            'mac_address': self._get_xml_text(host, "address[@addrtype='mac']", 'addr', default='N/A'),
            'vendor': self._get_xml_text(host, "address[@addrtype='mac']", 'vendor', default='N/A'),
            'hostnames': self._parse_hostnames(host),
            'ports': self._parse_ports(host),
        }
        result.update(self._extract_additional_info(host))
        return result

    def _get_xml_text(self, element, xpath, attribute, default=None):
        node = element.find(xpath)
        return node.get(attribute) if node is not None else default

    def _parse_hostnames(self, host):
        hostnames = host.find('hostnames')
        return [hostname.get('name')] if hostnames is not None else []

    def _parse_ports(self, host):
        ports = host.find('ports')
        return [self._parse_port(port) for port in ports.findall('port')] if ports is not None else []

    def _parse_port(self, port):
        return {
            'port_id': port.get('portid'),
            'protocol': port.get('protocol'),
            'state': self._get_xml_text(port, 'state', 'state', default='unknown'),
            'service': self._get_xml_text(port, 'service', 'name', default='N/A')
        }

    def _extract_additional_info(self, host):
        additional_info = {}
        for elem in host.iter('elem'):
            key = elem.get('key', 'unknown_key')
            value = elem.text or 'N/A'
            additional_info[key] = value
        return additional_info


def start_nmap_scan(target_ip, target_port, script_name):
    nmap_scan = NmapScanner()

    results_dir = 'results'
    os.makedirs(results_dir, exist_ok=True)

    xml_output_file = f'{results_dir}/scan_results_{script_name}.xml'
    current_time = datetime.now().isoformat()
    json_output_file = f'{results_dir}/scan_results_{current_time}.json'

    # Start the Nmap scan
    start_time = datetime.now().isoformat()
    print(f"Starting Nmap at {start_time}")
    print("-" * 30)

    # Run the scan with the specified IP, port, and script name
    nmap_scan.run_nmap_script(target_ip, target_port, script_name, xml_output_file)

    if os.path.exists(xml_output_file):
        print(f"XML output file '{xml_output_file}' generated.")
    else:
        print(f"Failed to generate XML output file '{xml_output_file}'. Exiting.")
        return

    scan_results = nmap_scan.parse_nmap_xml_file(xml_output_file)

    if scan_results:
        _print_scan_results(scan_results)
        nmap_scan.save_results_to_json(scan_results, json_output_file)
        print(f"Results saved to {json_output_file}")
    else:
        print(f"No results found in the XML file '{xml_output_file}'.")

    end_time = datetime.now().isoformat()
    duration = (datetime.fromisoformat(end_time) - datetime.fromisoformat(start_time)).seconds
    print(f"Nmap scan done: IP address scanned in {duration} seconds")


def _print_scan_results(scan_results):
    for result in scan_results:
        print(f"Nmap scan report for {result['ip_address']}")
        print("-" * 20)
        for key, value in result.items():
            if key == 'ports':
                for port in value:
                    print(f"Port: {port['port_id']}, Protocol: {port['protocol']}, State: {port['state']}, Service: {port['service']}")
            elif isinstance(value, list):
                print(f"{key.capitalize()}: {', '.join(value)}")
            else:
                print(f"{key.capitalize()}: {value}")
        print("-" * 20)
