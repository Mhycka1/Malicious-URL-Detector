
import pandas as pd
from urllib.parse import urlsplit
import pandas as pd
import numpy as np
import sklearn
import tensorflow as tf
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
import pickle

import re
from math import log2

# Transform dataset to dataframe format for easy manipulation
df = pd.read_csv('malicious_phish.csv')

copy = df.copy()

# Split the url into multiple parts for better processing from the neural net
copy['url'] = copy['url'].apply(urlsplit)

#split the tuple sections into seperate columns
copy['scheme'] = copy['url'].apply(lambda x: x[0])
copy['netloc'] = copy['url'].apply(lambda x: x[1])
copy['path'] = copy['url'].apply(lambda x: x[2])
copy['query'] = copy['url'].apply(lambda x: x[3])
copy['fragment'] = copy['url'].apply(lambda x: x[4])
copy.drop('url', axis=1, inplace=True)
copy['is_dangerous'] = copy['type'].apply(lambda x: 1 if x != 'benign' else 0)

#Feature extraction functions
def count_special_chars(text):
    return len(re.findall(r'[!@#$%^&*(),?":{}|<>]', text))

def count_path_segments(path):
    return len(path.split('/')) - 1

def calculate_entropy(text):
    if not text:
        return 0
    prob = [text.count(c) / len(text) for c in set(text)]
    return -sum(p * log2(p) for p in prob)


# Step 3: Apply feature extraction
copy['scheme_is_http'] = copy['scheme'].apply(lambda x: 1 if x == 'http' else 0)
copy['netloc_length'] = copy['netloc'].apply(len)
copy['netloc_has_digits'] = copy['netloc'].apply(lambda x: 1 if re.search(r'\d', x) else 0)
copy['path_length'] = copy['path'].apply(len)
copy['path_segments'] = copy['path'].apply(count_path_segments)
copy['query_length'] = copy['query'].apply(len)
copy['query_special_chars'] = copy['query'].apply(count_special_chars)
copy['fragment_length'] = copy['fragment'].apply(len)
copy['path_entropy'] = copy['path'].apply(calculate_entropy)

# Step 4: Prepare features and labels
X = copy[['scheme_is_http', 'netloc_length', 'netloc_has_digits', 'path_length', 
          'path_segments', 'query_length', 'query_special_chars', 
          'fragment_length', 'path_entropy']].values
y = copy['is_dangerous'].values

# Step 5: Split data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Step 6: Normalize features
scaler = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test = scaler.transform(X_test)

# Step 7: Build the neural network model
rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
rf_model.fit(X_train, y_train)

# Step 8: Evaluate the model
#y_pred = rf_model.predict(X_test)
#accuracy = accuracy_score(y_test, y_pred)
#print(f"Test Accuracy: {accuracy:.2f}")

pickle.dump(rf_model, open('ml_model.pkl', 'wb'))