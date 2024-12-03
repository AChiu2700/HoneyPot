import pandas as pd
import os
import time
from datetime import datetime
from datetime import timedelta
from datetime import timezone
from datetime import date
import pytz

tz = pytz.timezone('UTC')

today = (date.today()).isoformat()
recent_time = datetime.now(tz)

time_threshold= timedelta(minutes=15)
oldest_time = recent_time - time_threshold

filename = f'/home/cowrie/scripts/sanitized_logs/sanitized_{today}.csv'
log_file = pd.read_csv(filename)

reversed_log_file = log_file.iloc[::-1]

index_arr = []
for index, row in reversed_log_file.iterrows():

	try:
		format_timestamp = datetime.fromisoformat(row['timestamp'].replace('Z', '+00:00'))
		if format_timestamp >= oldest_time:
			index_arr.append(index)
		else:
			break
	except ValueError:
		print('value error')

latest_events = log_file.loc[index_arr]
# print(latest_events)

# Save the subset DataFrame to a new file (e.g., CSV)
latest_events.to_csv('/home/cowrie/scripts/latest_events.csv', index=False)
