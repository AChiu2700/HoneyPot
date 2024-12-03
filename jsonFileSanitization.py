import json
import csv
import os
from datetime import datetime, timedelta

# Function to generate file paths based on date range
def generate_file_paths(start_date, end_date, base_path, file_prefix):
    file_paths = []
    current_date = start_date
    while current_date <= end_date:
        file_name = f"{file_prefix}.{current_date.strftime('%Y-%m-%d')}"
        file_path = os.path.join(base_path, file_name)
        if os.path.exists(file_path):  # Check if the file exists
            file_paths.append(file_path)
        else:
            print(f"Warning: File {file_path} not found.")
        current_date += timedelta(days=1)
    return file_paths

# Function to validate date input
def get_valid_date(prompt):
    while True:
        date_input = input(prompt)
        try:
            return datetime.strptime(date_input, '%Y-%m-%d')
        except ValueError:
            print("Invalid date format. Please use YYYY-MM-DD.")

# Get user inputs for date range and output file name
start_date = get_valid_date("Enter the start date (YYYY-MM-DD): ")
end_date = get_valid_date("Enter the end date (YYYY-MM-DD): ")

if start_date > end_date:
    print("Error: Start date cannot be after end date.")
    exit()

output_file = input("Enter the output CSV file path: ")

# Base path and file prefix
base_path = '/home/achoo/Desktop/HoneyPot/cowrieLogs'
file_prefix = 'cowrie.json'

# Generate the list of input files
input_files = generate_file_paths(start_date, end_date, base_path, file_prefix)

# Ensure there are files to process
if not input_files:
    print("No files found for the specified date range.")
    exit()

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
        with open(input_file, 'r') as infile:
            for line in infile:
                try:
                    # Parse the JSON line
                    log_entry = json.loads(line)

                    # Extract relevant fields with default None if not present
                    csv_writer.writerow([
                        log_entry.get('eventid'),
                        log_entry.get('src_ip'),
                        log_entry.get('src_port'),
                        log_entry.get('dst_ip'),
                        log_entry.get('dst_port'),
                        log_entry.get('session'),
                        log_entry.get('protocol'),
                        log_entry.get('version'),
                        log_entry.get('hassh'),
                        log_entry.get('hasshAlgorithms'),
                        log_entry.get('message'),
                        log_entry.get('sensor'),
                        log_entry.get('timestamp')
                    ])
                except json.JSONDecodeError as e:
                    print(f"Error decoding JSON in file {input_file}: {e}")

# Indicate completion of the sanitization process
print(f"File sanitization complete.\nOutput saved to: {output_file}")