import re
import csv
import os

def parse_log_file(input_file, output_csv):
    # Regular expression patterns for validation
    email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'

    extracted_emails = set()
    extracted_ips = set()

    print(f"[*] Reading target file: {input_file}...")
    
    if not os.path.exists(input_file):
        print(f"[!] Error: {input_file} not found. Creating a dummy file for testing.")
        with open(input_file, 'w') as f:
            f.write("Sample breach data: admin@company.com leaked from IP 192.168.1.50\n")
            f.write("User breach data: hacker_target@gmail.com linked to malicious IP 10.0.0.1\n")

    # Read and scan the file
    with open(input_file, 'r', encoding='utf-8', errors='ignore') as file:
        for line in file:
            emails = re.findall(email_pattern, line)
            ips = re.findall(ip_pattern, line)
            
            for email in emails:
                extracted_emails.add(email)
            for ip in ips:
                extracted_ips.add(ip)

    # Write the results to a CSV spreadsheet
    print(f"[*] Writing extracted intelligence to {output_csv}...")
    with open(output_csv, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Type", "Indicator of Compromise (IoC)"])
        
        for email in extracted_emails:
            writer.writerow(["Email Address", email])
        for ip in extracted_ips:
            writer.writerow(["IP Address", ip])

    print(f"[+] Success! Extracted {len(extracted_emails)} emails and {len(extracted_ips)} IPs.")

if __name__ == "__main__":
    # Define your input leak file and desired output destination
    target_data = "breach_dump.txt"
    output_results = "extracted_intel.csv"
    
    parse_log_file(target_data, output_results)