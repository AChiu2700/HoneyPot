# %%
import pandas as pd
import re
import pickle
import json
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

# Load the test data
test_data = pd.read_csv('/home/cowrie/scripts/latest_events.csv', delimiter=',', header=None)
test_data.columns = ['eventid', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'session', 
                     'protocol', 'version', 'hassh', 'hasshAlgorithms', 'message', 
                     'sensor', 'timestamp']

# Define malicious keywords and whitelist phrases as in the original code
malicious_keywords = ['failed', 'whoami', 'uname', 'chattr', 'cat', ' rm', '.ssh', 'authorized_keys',
                      'grep', 'chmod', 'curl', 'not found', 'mkdir', '/bin/', '/tmp/', 'sshd', '.sh', 
                      'ssh-rsa', 'ps', 'crontab', 'uptime', 'ifconfig', 'cpuinfo', 'df', 'chpasswd', 
                      'free', 'pkill', 'pgrep', 'admin']

whitelist_phrases = ["SSH client hassh fingerprint", "New connection"]

# Define the function to flag malicious messages
def flag_malicious(message):
    if any(phrase in message for phrase in whitelist_phrases):
        return 0
    if any(keyword in message for keyword in malicious_keywords):
        return 1
    failed_login_pattern = r'login attempt \[root\/[^\]]+\] failed'
    if re.search(failed_login_pattern, message):
        return 1
    return 0
    
# Apply the flag_malicious function to the 'message' column
test_data['attack'] = test_data['message'].apply(flag_malicious)

# Keep only selected columns
test_data = test_data[['message', 'hasshAlgorithms', 'eventid', 'protocol', 'attack']]

# %%
# Initialize the LabelEncoder to encode categorical columns
le = LabelEncoder()

# Encode categorical columns (hasshAlgorithms, eventid, protocol)
test_data['hasshAlgorithms'] = le.fit_transform(test_data['hasshAlgorithms'])
test_data['eventid'] = le.fit_transform(test_data['eventid'])
test_data['protocol'] = le.fit_transform(test_data['protocol'])

# Separate features (X) and labels (y)
X_test = test_data.drop(['attack', 'message'], axis=1)
y_test = test_data['attack']

# Initialize StandardScaler to scale feature data
scaler = StandardScaler()
X_test_scaled = scaler.fit_transform(X_test)

# Load the saved model
with open('finalized_model_Voting.sav', 'rb') as file:
    voting_clf = pickle.load(file)

# %%
# Make predictions on the test set using the model
y_pred_voting = voting_clf.predict(X_test_scaled)

# Evaluate the model on the test data
print("Voting Classifier (Soft) Evaluation:")
print(f"Accuracy: {accuracy_score(y_test, y_pred_voting):.4f}")
#print(confusion_matrix(y_test, y_pred_voting))
# print(classification_report(y_test, y_pred_voting))

# Add predictions from the Voting Classifier as a new column 'attack' in the original data
test_data['attack'] = y_pred_voting

# %%
# Reload the original test data from the CSV file
# original_test_data = pd.read_csv('test_sanitized_logs_combined.csv', delimiter=',', header=None)
original_test_data = pd.read_csv('/home/cowrie/scripts/latest_events.csv', delimiter=',', header=None)
original_test_data.columns = ['eventid', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'session', 
                               'protocol', 'version', 'hassh', 'hasshAlgorithms', 'message', 
                               'sensor', 'timestamp']

# Append the Voting Classifier's results for 'attack' to the original test_data
original_test_data['attack'] = y_pred_voting

# Convert the dataframe to a JSON format
test_data_with_voting_json = original_test_data[['eventid', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 
                                                 'session', 'protocol', 'message', 'sensor', 'timestamp', 
                                                 'attack']]
# print(test_data_with_voting_json)
# Save the JSON to a file
test_data_with_voting_json.to_json('/home/cowrie/scripts/latest_votingClasifer_Predictions.json', orient='records', indent=3)
# %%
