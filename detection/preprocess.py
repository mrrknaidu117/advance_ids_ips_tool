import os
import pandas as pd
import yaml
from sklearn.preprocessing import LabelEncoder, StandardScaler

# Load YAML config
with open("config.yaml") as f:
    cfg = yaml.safe_load(f)

DATASET_PATH = cfg["DATASET_PATH"]

def load_and_preprocess(filename):
    path = os.path.join(DATASET_PATH, filename)
    df = pd.read_csv(path, low_memory=False)

    df = df.drop(columns=[col for col in df.columns if 'Unnamed' in col], errors='ignore')
    df = df.replace([float('inf'), float('-inf')], None)
    df = df.dropna()

    df['Label'] = df['Label'].apply(lambda x: 'Normal' if x.upper() == 'BENIGN' else 'Attack')
    y = LabelEncoder().fit_transform(df['Label'])

    df = df.drop(columns=['Label'])
    X = df.select_dtypes(include=['float64', 'int64'])

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    return X_scaled, y, scaler
