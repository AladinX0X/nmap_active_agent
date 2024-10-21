# Nmap Active Scan Agent

## Project Overview

This tool provides a modular and extensible way to perform network scanning using Nmap. It can:
- Execute Nmap scans on specific IP addresses and ports at regular intervals.
- Parse the Nmap XML output to extract host, port, and detailed hardware information (like "Module", "Version", "Serial Number", etc.).
- Save the parsed results in JSON format with filenames based on the current timestamp.
- Display the scan results in a formatted manner on the console and log scan progress and errors using Loguru.

## Directory Structure

```
Active Scan Agent
|__ scripts/
|    |__ script1
|    |__ script2
|    |__ ...
|__ results/
|    |__ parsed_scan_results_<timestamp>.json
|    |__ scan_results_<script_name>.xml
|__ run/
|    |__ nmap_agent.py
|    |__ run.py
|    |__ config.json
|__ README.md
|__ requirements.txt
```

- `scripts/`: Directory for storing various Nmap scripts.
- `results/`: Directory for storing XML and JSON scan results.
- `run/nmap_agent.py`: Contains the main logic and class implementations for running and parsing Nmap scans.
- `run/run.py`: Executes the Nmap scanning process using configuration from `config.json`.
- `run/config.json`: Config file to easily adjust scan parameters (target IP, port, script name, and scan interval).

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
    "target_ip": "192.168.0.1",
    "target_port": 102,
    "script_name": "s7-info",
    "wait_time_minutes": 5
}
```

You can easily modify this file to change the target IP, port, Nmap script, and scan interval.

## Usage

1. **Configure the scan parameters**:
   - Modify the `config.json` file with the desired target IP, port, script, and scan interval.

2. **Run the scan**:
   
   Navigate to the `run/` directory and run the script:

   ```bash
   python run.py
   ```

   The scan will run continuously based on the interval specified in `config.json`.

3. **View Results**:
    - The XML results are stored in the `results/` directory with filenames like `scan_results_<script_name>.xml`.
    - The parsed JSON results are also saved in the `results/` directory with filenames based on the timestamp of the scan.
    - Results will also be displayed in the terminal for each scan.
    - Logs for each scan (including any errors) are also displayed in the terminal and can be saved for later review (if configured).

## Configuration

- You can configure the Nmap scan by modifying the `config.json` file. This file allows you to change the `target_ip`, `target_port`, `script_name`, and `wait_time_minutes` to customize the scan.

## Logging and Error Handling

- The project uses the `loguru` library for improved logging and error handling. By default, logs are output to the console, showing the scan progress, errors, and detailed results. You can configure Loguru to also save logs to a file.
- Log messages show scan progress, errors, and results in the console.

## How It Works

1. **Initialization**: The `NmapScan` class in `nmap_agent.py` builds and runs the Nmap command.
2. **Execution**: The `run_nmap_script()` method executes the Nmap command and writes the output to an XML file.
3. **Parsing**: The `parse_nmap_xml_file()` method parses the XML file to extract details about hosts, ports, and other network information, including NSE script output.
4. **Saving Results**: The parsed results are saved in JSON format using the `save_results_to_json()` method.
5. **Continuous Scanning**: The `run.py` script runs in a loop, scanning at intervals based on the configuration file.