import json
import os
from datetime import date

today = (date.today()).isoformat()

input_json = '/home/cowrie/scripts/latest_votingClasifer_Predictions.json'
output_json = f'/home/cowrie/scripts/attacks/events_attack_{today}.json'

def write_json(new_data, filename):
	if not os.path.exists(filename):
		with open(filename, "w") as f:
			json.dump([], f)  # Create an empty JSON object in the file

	with open(filename,'r+') as file:

		file_data = json.load(file)

		# print(new_data)
		file_data.append(new_data)
		# Sets file's current position at offset.
		file.seek(0)
		# convert back to json.
		json.dump(file_data, file, indent = 4)

# Open the JSON file
with open(input_json, 'r') as f:
    # Load the JSON data into a Python dictionary
    data = json.load(f)
   #  print(data)

for event in data:
	if event['attack']:
		write_json(event, output_json)
