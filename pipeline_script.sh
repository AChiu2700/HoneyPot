#!/bin/bash

echo "Honeypot Pipeline Bash Script!"
/usr/bin/python3 /home/cowrie/scripts/printTime.py >> /home/cowrie/scripts/last_cron_time

# Read cowrie log file and sanitize data
/usr/bin/python3 /home/cowrie/scripts/jsonFileSanitization.py
echo "Sanitized data to csv"

# Read last n minutes of log (set to 15 minutes)
/home/cowrie/scripts/scripts-env/bin/python3 /home/cowrie/scripts/latestLogEvent.py
echo "Finished Latest Log Event"

# Run latest events through machine learning model - Voting Classifier (Soft) Evaluation
/home/cowrie/scripts/scripts-env/bin/python3 /home/cowrie/scripts/TestML.py >> /home/cowrie/scripts/TestML_output.txt
echo "Finished Test ML"

# Separate events by attack into attacks file
/home/cowrie/scripts/scripts-env/bin/python3 /home/cowrie/scripts/EventAttack.py
echo "Finished Event Attack"
