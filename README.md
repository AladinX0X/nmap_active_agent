# Nmap Active Scan Agent

## Project Overview

This tool provides a modular and extensible way to perform network scanning using Nmap. It can:
- Execute Nmap scans on specific IP addresses and ports at regular intervals.
- Parse the Nmap XML output to extract host, port, and detailed hardware information (like "Module", "Version", "Serial Number", etc.).
- Save the parsed results in JSON format with filenames based on the current timestamp.
- Display the scan results in a formatted manner on the console and log scan progress and errors using Python's `logging` library.

## Directory Structure

```
Nmap Active Scan Agent
|__ scripts/
|    |__ script1
|    |__ script2
|    |__ ...
|__ results/
|    |__ parsed_scan_results_<timestamp>.json
|    |__ scan_results_<ip>_<script_name>.xml
|__ nmap_agent/
|    |__ nmap_agent.py
|    |__ run.py
|    |__ config.json
|__ README.md
|__ requirements.txt
```

- `scripts/`: Directory for storing various Nmap scripts.
- `results/`: Directory for storing XML and JSON scan results.
- `nmap_agent/`: Contains the main logic for running scans and managing configurations.
- `config.json`: Config file to easily adjust scan parameters (target IP, port, script name, and scan interval).

## Installation

### Prerequisites

- **Python 3.10+**: Ensure Python is installed on your system.
- **Nmap**: The Nmap tool must be installed and accessible via the command line.
- **Python Libraries**: Install the required Python libraries by running the following command:

    ```bash
    pip install -r requirements.txt
    ```

### Config.json File

The `config.json` file contains the parameters for the scan:

```json
{
    "wait_time_minutes": 5,
    "scans": [
        {
            "target_ip": ["192.168.0.1"],
            "target_port": 102,
            "script_name": ["pn-discovery"]
        },
        {
            "target_ip": ["192.168.0.2"],
            "target_port": 101,
            "script_name": ["s7-info"]
        }
    ]
}
```

You can easily modify this file to change the target IP, port, Nmap script, and scan interval.

## Usage

1. **Configure the scan parameters**:
   - Modify the `config.json` file with the desired target IP, port, script, and scan interval.

2. **Run the scan**:
   
   Navigate to the `nmap_agent/` directory and run the script:

   ```bash
   python run.py
   ```

   The scan will run continuously based on the interval specified in `config.json`.

3. **View Results**:
    - The XML results are stored in the `results/` directory with filenames like `scan_results_<ip>_<script_name>.xml`.
    - The parsed JSON results are also saved in the `results/` directory with filenames based on the timestamp of the scan.
    - Results will also be displayed in the terminal for each scan.
    - Logs for each scan (including any errors) are also displayed in the terminal.

## Configuration

- You can configure the Nmap scan by modifying the `config.json` file. This file allows you to change the `target_ip`, `target_port`, `script_name`, and `wait_time_minutes` to customize the scan.

## Logging and Error Handling

- The project uses Python's `logging` library for improved logging and error handling. Logs are output to the console, showing the scan progress, errors, and detailed results.

## How It Works

1. **Initialization**: The `run_nmap_script` function builds and runs the Nmap command.
2. **Execution**: It executes the Nmap command and writes the output to an XML file.
3. **Parsing**: The `parse_nmap_xml_file` function parses the XML file to extract details about hosts, ports, and other network information.
4. **Saving Results**: The parsed results are saved in JSON format using the `save_results_to_json` function.
5. **Continuous Scanning**: The `start_scan_loop` function runs in a loop, scanning at intervals based on the configuration file.
6. **Cleanup**: The `cleanup_old_xml_files` function ensures only the latest XML files are retained, automatically deleting older files after a specified number of scans.

## Example JSON Output

The scan results are saved in JSON format with detailed information extracted from the Nmap scan:

```json
{
    "wait_time_minutes": 5,
    "scans": [
        {
            "target_ip": "192.168.0.1",
            "target_port": 102,
            "script_name": "pn-discovery",
            "results": [
                {
                    "ip_address": "192.168.0.1",
                    "mac_address": "XX:XX:XX:XX:XX:XX",
                    "vendor": "Vendor Name",
                    "Module": "Model XYZ",
                    "Version": "1.0",
                    "System Name": "System ABC",
                    "Serial Number": "123456789",
                    "hostnames": [],
                    "ports": [
                        {
                            "port_id": "102",
                            "protocol": "tcp",
                            "state": "open",
                            "service": "iso-tsap"
                        }
                    ]
                }
            ]
        }
    ]
}
```

This JSON output provides detailed information about the scanned device, including module type, version, and network service details.

## Testing

- **Mocking Subprocess Calls**: For unit testing, you can mock the `subprocess.run` function using `unittest.mock` to simulate different Nmap outputs without needing to run actual scans.

## Type Checking

- The codebase includes type hints, which can be validated using `mypy` for improved type checking and safety:

    ```bash
    mypy nmap_agent/
    ```
