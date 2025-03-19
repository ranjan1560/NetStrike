import sys
import os
import subprocess
import re

port_files = {}
DEFAULT = "\033[0m"
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
MAGENTA = "\033[95m"
BLINK = "\033[5m"
CYAN = "\033[96m"
GRAY = "\033[90m"
BOLD = "\033[1m"
RESET = "\033[0m"
BLUE = "\033[34m"

def display_banner():
        banner = r'''
                 {6}  /\_/\  
                 {6} (  = ◉_◉)🔍  
                 {6}  |  {1}[🕵️] |  {1}NetStrike v1.0  
                 {1}-----------------------------  
                 {3}Tool   : {2}NetStrike  
                 {3}Author : {2}Ranjan Kumar  
                 {3}Version: {2}1.0  
                 {3}GitHub : {2}https://github.com/ranjan1560  
                 {3}Twitter: {2}@ranjan_049  
                 {1}-----------------------------
        '''.format(DEFAULT, GREEN, RED, YELLOW, MAGENTA, BLINK, CYAN)

        print(banner)

def read_file(file_name):
    data = []
    with open(file_name, 'r') as file:
        for line in file:
            line = line.strip()
            if line:
                parts = line.split(':')
                if len(parts) == 2:
                    hostname = parts[0]
                    port = parts[1]
                    data.append({'hostname': hostname, 'port': port})
                else:
                    print(f"Issue parsing line: {line}")
    return data

def save_to_port_files(data):
    global port_files
    directory = 'domain_list'
    try:
        if not os.path.exists(directory):
            os.makedirs(directory)
        else:
            files = os.listdir(directory)
            for file in files:
                file_path = os.path.join(directory, file)
                if os.path.isfile(file_path):
                    os.remove(file_path)

        for item in data:
            hostname = item['hostname']
            port = item['port']

            if port not in port_files:
                file_name = f"{directory}/port{port}.txt"
                port_files[port] = open(file_name, 'a')

            file = port_files[port]
            file.write(hostname + '\n')

    except Exception as e:
        print(f"Error: {e}")

    finally:
        for file in port_files.values():
            file.close()


def run_nmap_scan(directory):
    nmap_directory = 'nmap_result'
    try:
        if not os.path.exists(nmap_directory):
            os.makedirs(nmap_directory)
        else:
            files = os.listdir(nmap_directory)
            for file in files:
                file_path = os.path.join(nmap_directory, file)
                if os.path.isfile(file_path):
                    os.remove(file_path)

        for filename in os.listdir(directory):
            if filename.startswith("port") and filename.endswith(".txt"):
                port = filename[4:-4]
                filepath = os.path.join(directory, filename)
                nmap_output_file = f"nmap_{filename[:-4]}.txt"
                nmap_output_path = os.path.join(nmap_directory, nmap_output_file)
                command = f"nmap -p{port} -sCV -Pn -iL {filepath} -oN {nmap_output_path}"
                print(f"{CYAN}{BOLD}Processing your request...{RESET}")
                print(f"{RED}Please sit back and relax while we handle the operations.{RESET}")
                print(f"{MAGENTA}This may take a moment. Thank you for your patience! 🚀{RESET}")
                print()
                subprocess.run(command, shell=True)
                print()

    except Exception as e:
        print(f"Error: {e}")

def parse_nmap_output(file_path):
    with open(file_path, 'r') as file:
        lines = file.readlines()

    results = []
    current_domain = ""
    current_ip = ""
    current_port = ""
    current_state = ""
    current_service = ""
    current_version = ""
    issue_name = ""

    for line in lines:
        domain_match = re.search(r"Nmap scan report for (.+) \(([\d\.]+)\)", line)
        if domain_match:
            if current_domain and current_state == "open" and current_service not in ["unknown", "ssl", "http"] and not (current_service == "tcpwrapped" or (current_service == "ssl" and current_port == "443/tcp")):
                if "submission?" in current_service:
                    issue_name = "Sensitive Port Publicly Exposed"
                else:
                    issue_name = f"{current_service.capitalize()} server publicly exposed"
                results.append({
                    "DOMAIN": current_domain,
                    "IP": current_ip,
                    "PORT": current_port,
                    "STATE": current_state,
                    "SERVICE": current_service,
                    "VERSION": current_version,
                    "ISSUE NAME": issue_name
                })
            current_domain = domain_match.group(1)
            current_ip = domain_match.group(2)
            current_port = ""
            current_state = ""
            current_service = ""
            current_version = ""
            issue_name = ""
            continue

        port_match = re.search(r"(\d+/tcp)\s+(\w+)\s+(\S+)(.*)", line)
        if port_match:
            current_port = port_match.group(1)
            current_state = port_match.group(2)
            current_service = port_match.group(3).replace("?", "")
            current_version = port_match.group(4).strip() if port_match.group(4).strip() else "Unknown"
            continue

    if current_domain and current_state == "open" and current_service not in ["unknown", "ssl", "http"] and not (current_service == "tcpwrapped" or (current_service == "ssl" and current_port == "443/tcp")):
        if "submission?" in current_service:
            issue_name = "Sensitive Port Publicly Exposed"
        else:
            issue_name = f"{current_service.capitalize()} server publicly exposed".replace("?", "")
        results.append({

            "DOMAIN": current_domain,
            "IP": current_ip,
            "PORT": current_port,
            "STATE": current_state,
            "SERVICE": current_service,
            "VERSION": current_version,
            "ISSUE NAME": issue_name
        })

    return results

def format_output(results):
    formatted_results = []
    for result in results:
        formatted_result = (
            # "=" * 60 + "\n"
            f"ISSUE NAME:- {result['ISSUE NAME']}\n"
            f"DOMAIN:- {result['DOMAIN']} ({result['IP']})\n"
            f"PORT:- {result['PORT']}\n"
            f"STATE:- {result['STATE']}\n"
            f"SERVICE:- {result['SERVICE']}\n"
            f"VERSION:- {result['VERSION']}\n"
            # "=" * 60 + "\n"
        )
        formatted_results.append(formatted_result)
    return formatted_results
display_banner()
def filter_nmap_results(nmap_result_folder):
    filtered_result_directory = 'filtered_result'
    if not os.path.exists(filtered_result_directory):
        os.makedirs(filtered_result_directory)

    all_results_path = os.path.join(filtered_result_directory, "all.txt")

    with open(all_results_path, 'w') as all_file:
        for file_name in os.listdir(nmap_result_folder):
            nmap_result_file = os.path.join(nmap_result_folder, file_name)
            with open(nmap_result_file, 'r') as file:
                all_file.write(file.read() + '\n')

    results = parse_nmap_output(all_results_path)
    formatted_results = format_output(results)

    nmap_filtered_path = os.path.join(filtered_result_directory, "nmap_filtered_result.txt")
    with open(nmap_filtered_path, 'w') as filtered_file:
        for result in formatted_results:
            filtered_file.write(result + '\n')

    print(f"Scan completed and result saved in {nmap_filtered_path}")

    input_file = "filtered_result/nmap_filtered_result.txt"
    output_file = "filtered_result/final.txt"

    current_issue = ""
    issue_domains_map = {}
    domain = ""

    with open(input_file, "r") as infile, open(output_file, "w") as outfile:
        for line in infile:

            line = line.strip()

            if line.startswith("ISSUE NAME:-"):
                current_issue = line
                if current_issue not in issue_domains_map:
                    issue_domains_map[current_issue] = []

            elif line.startswith("DOMAIN:-"):
                domain = line.split(":-")[1].split()[0]
            elif line.startswith("PORT:-"):
                port = line.split(":-")[1].strip()
                if domain and port:
                    if current_issue:
                        issue_domains_map[current_issue].append(f"{domain}:{port}")
                    else:
                        print(f"Warning: DOMAIN and PORT found without an ISSUE NAME. Skipping: {domain}:{port}")


        first_issue = True
        for issue, domains in issue_domains_map.items():
            if not first_issue:
                outfile.write("\n---------------------------------------------------\n")
            first_issue = False
            outfile.write(f"{issue}\nDomains:-\n")
            outfile.write("\n".join(domains) + "\n")

    print(f"Formatted results have been saved to {output_file}.")



def main():
    if len(sys.argv) != 2:
        print("Usage: python3 script.py <input_file>")
        sys.exit(1)

    file_path = sys.argv[1]

    data = read_file(file_path)
    save_to_port_files(data)

    run_nmap_scan('domain_list')
    filter_nmap_results('nmap_result')

if __name__ == "__main__":
    main()
