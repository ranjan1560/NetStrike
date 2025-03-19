# NetStrike: Automated Nmap Scanning and Port Filtering

## Overview

NetStrike is a powerful **network reconnaissance tool** designed for *cybersecurity enthusiasts, security researchers and penetration testers. It automates port scanning, result filtering, and structured reporting, helping security professionals efficiently analyze network exposure and identify potential risks.

## Requirements

- Python 3.x
- Nmap installed on the system

## Installation

1. Ensure Python 3.x is installed.
2. Install Nmap if not already installed:
   ```sh
   sudo apt install nmap  # Debian-based systems
   brew install nmap  # macOS
3. Save the script as netstrike.py.

## Usage

- Run the script with the input file containing hostnames and ports:
 ``` python3 netstrike.py <filename.txt> ```

## Input File Format
- The input file should contain lines in the format:
  ``` file.txt 
   example.com:80  
   example.net:443
 OR
   ``` The Naabu output file can be directly fed into NetStrike: ```
   
NetStrike will automatically process the results and perform further analysis.

## How It Works
Step 1: Reading and Organizing Data:
  - NetStrike reads the input file and extracts hostnames and ports.
  - It creates individual files for each port in a domain_list directory.
    
Step 2: Running Nmap Scans:
  - Nmap is executed for each port-specific file.
  - Results are stored in the nmap_result directory.
    
Step 3: Parsing and Filtering Nmap Results
  - NetStrike analyzes the scan data and identifies exposed services that may pose security risks.

Step 4: Output Formatting:
  - The findings are structured into:
      -- filtered_result/nmap_filtered_result.txt (detailed scan results)
      -- filtered_result/final.txt (aggregated issues and affected domains)


## Why Use NetStrike?
- Comprehensive Network Analysis: Quickly identifies exposed services across multiple domains.
- Automation: Reduces manual effort by automating scanning, filtering, and result aggregation.
- Enhanced Prioritization: Focuses on critical vulnerabilities while eliminating unnecessary noise.
- Scalability: Efficiently handles large-scale scans, making it ideal for enterprise security teams and researchers.
- Actionable Insights: Structured reporting helps security teams quickly identify and mitigate risks.
