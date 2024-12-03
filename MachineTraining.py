# %%
import pandas as pd
import numpy as np
import re  # Added for regex operations
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.svm import SVC  # Importing SVM
import warnings

# Ignore warnings
warnings.filterwarnings("ignore")

# %%
# Load data
data = pd.read_csv('sanitized_logs_combined.csv', delimiter=',', header=None)
data.columns = ['eventid', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'session', 
                'protocol', 'version', 'hassh', 'hasshAlgorithms', 'message', 
                'sensor', 'timestamp']

# Check initial shape of data
print(f"Initial shape of data: {data.shape}")

# Define keywords that indicate malicious activity
malicious_keywords = ['failed', 'whoami', 'uname', 'chattr', 'cat', ' rm', '.ssh', 'authorized_keys',
                      'grep', 'chmod', 'curl', 'not found', 'mkdir', '/bin/', '/tmp/', 'sshd', '.sh', 
                      'ssh-rsa', 'ps', 'crontab', 'uptime', 'ifconfig', 'cpuinfo', 'df', 'chpasswd', 
                      'free', 'pkill', 'pgrep', 'admin']

# Define whitelist phrases to ignore
whitelist_phrases = ["SSH client hassh fingerprint", "New connection"]

# Define a function to check for malicious activity with a whitelist
def flag_malicious(message):
    # Skip messages that contain any whitelisted phrases
    if any(phrase in message for phrase in whitelist_phrases):
        return 0
    # Check for malicious keywords
    if any(keyword in message for keyword in malicious_keywords):
        return 1
    # Check for failed login attempts with random values
    failed_login_pattern = r'login attempt \[root\/[^\]]+\] failed'
    if re.search(failed_login_pattern, message):
        return 1
    return 0

# Create a target column based on the presence of malicious keywords in the 'message' column
data['attack'] = data['message'].apply(flag_malicious)

# Keep only selected columns
data = data[['message', 'hasshAlgorithms', 'eventid', 'protocol', 'attack']]

# %%
# Initialize a LabelEncoder to encode categorical columns
le = LabelEncoder()

# Encode categorical columns (hasshAlgorithms, eventid, protocol)
data['hasshAlgorithms'] = le.fit_transform(data['hasshAlgorithms'])
data['eventid'] = le.fit_transform(data['eventid'])
data['protocol'] = le.fit_transform(data['protocol'])

# Separate the data into two groups: class 0 (non-malicious) and class 1 (malicious)
class_0 = data[data['attack'] == 0]
class_1 = data[data['attack'] == 1]

# Randomly undersample class 0 to match the number of instances in class 1
class_0_balanced = class_0.sample(n=len(class_1), random_state=42)

# Combine the balanced classes back together
balanced_data = pd.concat([class_0_balanced, class_1])

# Shuffle the balanced dataset
balanced_data = balanced_data.sample(frac=1, random_state=42).reset_index(drop=True)

# Separate features (X) and labels (y)
X = balanced_data.drop(['attack', 'message'], axis=1)  # Drop 'message' column as we no longer need it
y = balanced_data['attack']

# Initialize StandardScaler to scale feature data
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Split data into train and validation sets
X_train, X_val, y_train, y_val = train_test_split(X_scaled, y, test_size=0.2, random_state=42, stratify=y)

# %%
# Initialize Support Vector Machine Classifier
model_svm = SVC(probability=True, random_state=42)  # Enable probability estimates

# Train the model
model_svm.fit(X_train, y_train)

# Predict on validation set
y_pred_svm = model_svm.predict(X_val)

# Evaluate the SVM model
print("SVM Classifier Evaluation:")
print(f"Accuracy: {accuracy_score(y_val, y_pred_svm):.4f}")
print(confusion_matrix(y_val, y_pred_svm))
print(classification_report(y_val, y_pred_svm))

# Initialize XGBoost Classifier
model_xgb = XGBClassifier(use_label_encoder=False, eval_metric='logloss', random_state=42)

# Train the model
model_xgb.fit(X_train, y_train)

# Predict on validation set
y_pred_xgb = model_xgb.predict(X_val)

# Evaluate the XGBoost model
print("XGBoost Classifier Evaluation:")
print(f"Accuracy: {accuracy_score(y_val, y_pred_xgb):.4f}")
print(confusion_matrix(y_val, y_pred_xgb))
print(classification_report(y_val, y_pred_xgb))

# Initialize Random Forest Classifier
model_rf = RandomForestClassifier(random_state=42)

# Train the Random Forest model
model_rf.fit(X_train, y_train)

# Predict on validation set
y_pred_rf = model_rf.predict(X_val)

# Evaluate the Random Forest model
print("Random Forest Classifier Evaluation:")
print(f"Accuracy: {accuracy_score(y_val, y_pred_rf):.4f}")
print(confusion_matrix(y_val, y_pred_rf))
print(classification_report(y_val, y_pred_rf))

# Initialize VotingClassifier with soft voting
voting_clf = VotingClassifier(
    estimators=[('svm', model_svm), ('xgb', model_xgb), ('rf', model_rf)],
    voting='soft'
)

# Train the VotingClassifier
voting_clf.fit(X_train, y_train)

# Predict on validation set
y_pred_voting = voting_clf.predict(X_val)

# Evaluate the Voting Classifier
print("Voting Classifier (Soft) Evaluation:")
print(f"Accuracy: {accuracy_score(y_val, y_pred_voting):.4f}")
print(confusion_matrix(y_val, y_pred_voting))
print(classification_report(y_val, y_pred_voting))

# %%
# Import necessary libraries for saving models
import pickle

# Save the trained models to disk
filename_xgb = 'finalized_model_XGB.sav'
filename_svm = 'finalized_model_SVM.sav'
filename_rf = 'finalized_model_RF.sav'
filename_voting = 'finalized_model_Voting.sav'

# %%
# Confirm models have been saved successfully
print("Models have been saved successfully.")

# Save each model using pickle
with open(filename_xgb, 'wb') as file:
    pickle.dump(model_xgb, file)

with open(filename_svm, 'wb') as file: 
    pickle.dump(model_svm, file)

with open(filename_rf, 'wb') as file:  
    pickle.dump(model_rf, file)

with open(filename_voting, 'wb') as file:
    pickle.dump(voting_clf, file)

# %%
