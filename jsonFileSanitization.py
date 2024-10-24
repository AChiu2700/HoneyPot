import json
import csv
import os

# List of input JSON log files
input_files = [
    '/home/achoo/Desktop/Honeypot/cowrieLogs/cowrie.json.2024-10-12',
    '/home/achoo/Desktop/Honeypot/cowrieLogs/cowrie.json.2024-10-13'
]

    # '/home/achoo/Desktop/Honeypot/cowrieLogs/cowrie.json.2024-10-06',
    # '/home/achoo/Desktop/Honeypot/cowrieLogs/cowrie.json.2024-10-07',
    # '/home/achoo/Desktop/Honeypot/cowrieLogs/cowrie.json.2024-10-08',
    # '/home/achoo/Desktop/Honeypot/cowrieLogs/cowrie.json.2024-10-09'


output_file = '/home/achoo/Desktop/Honeypot/test3_sanitized_logs_combined.csv'
#output_file = '/home/achoo/Desktop/Honeypot/sanitized_logs_combined.csv'

# Open the output CSV file
with open(output_file, 'w', newline='') as outfile:
    # Create a CSV writer
    csv_writer = csv.writer(outfile)

    # Write the CSV header
    csv_writer.writerow([
        'eventid', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'session', 'protocol',
        'version', 'hassh', 'hasshAlgorithms', 'message', 'sensor', 'timestamp'
    ])

    # Iterate over each input file
    for input_file in input_files:
        # Open the input JSON file
        with open(input_file, 'r') as infile:
            # Iterate over each line in the JSON file
            for line in infile:
                try:
                    # Parse the JSON line
                    log_entry = json.loads(line)

                    # Extract relevant fields with default None if not present
                    eventid = log_entry.get('eventid')
                    src_ip = log_entry.get('src_ip')
                    src_port = log_entry.get('src_port')
                    dst_ip = log_entry.get('dst_ip')
                    dst_port = log_entry.get('dst_port')
                    session = log_entry.get('session')
                    protocol = log_entry.get('protocol')
                    version = log_entry.get('version')
                    hassh = log_entry.get('hassh')
                    hasshAlgorithms = log_entry.get('hasshAlgorithms')
                    message = log_entry.get('message')
                    sensor = log_entry.get('sensor')
                    timestamp = log_entry.get('timestamp')

                    # Write the extracted fields to the CSV
                    csv_writer.writerow([
                        eventid, src_ip, src_port, dst_ip, dst_port, session, protocol,
                        version, hassh, hasshAlgorithms, message, sensor, timestamp
                    ])
                
                except json.JSONDecodeError as e:
                    print(f"Error decoding JSON in file {input_file}: {e}")
