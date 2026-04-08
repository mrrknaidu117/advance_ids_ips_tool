import os
import yaml
import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
import numpy as np

# ---- load config ----
cfg_path = os.path.join(os.path.dirname(__file__), "..", "config.yaml")
with open(cfg_path, 'r') as f:
    cfg = yaml.safe_load(f)

# Convert relative paths to absolute paths
base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET_PATH = os.path.join(base_dir, cfg["DATASET_PATH"])
MODEL_PATH = os.path.join(base_dir, cfg["MODEL_PATH"])

print("⚙️ Loading entire dataset with all features")

# peek at one file to get the exact headers
first_csv = next(f for f in os.listdir(DATASET_PATH) if f.lower().endswith(".csv"))
sample = pd.read_csv(os.path.join(DATASET_PATH, first_csv), nrows=0)
all_cols = sample.columns.tolist()

# Identify the label column (assuming it's named 'Label' in some form)
label_col = None
for col in all_cols:
    if col.lower() == 'label':
        label_col = col
        break

if not label_col:
    raise RuntimeError("Could not find 'Label' column in dataset")

print(f"⚙️ Found label column: {label_col}")
print(f"⚙️ Total features: {len(all_cols)-1}")


# ---- load and process CSVs in chunks ----
print("⚙️ Processing dataset files in chunks to avoid memory issues")

# Initialize empty DataFrames for collecting samples
sampled_data = pd.DataFrame()
chunk_size = 10000  # Adjust based on available memory

# Process each CSV file
for fn in sorted(os.listdir(DATASET_PATH)):
    if not fn.lower().endswith(".csv"):
        continue
    path = os.path.join(DATASET_PATH, fn)
    try:
        print(f"Processing {fn} in chunks...")
        # Read and sample from each chunk
        chunk_reader = pd.read_csv(path, chunksize=chunk_size, low_memory=False)
        file_sample = pd.DataFrame()
        
        for i, chunk in enumerate(chunk_reader):
            # Take a small sample from each chunk
            sample_size = min(1000, len(chunk))
            if len(chunk) > 0:
                chunk_sample = chunk.sample(n=sample_size, random_state=42) if len(chunk) > sample_size else chunk
                file_sample = pd.concat([file_sample, chunk_sample], ignore_index=True)
            
            # Print progress indicator
            if i % 10 == 0:
                print(f"  Processed {i} chunks...")
        
        # Add this file's samples to our dataset
        sampled_data = pd.concat([sampled_data, file_sample], ignore_index=True)
        print(f"  ✅ Sampled {len(file_sample)} records from {fn}")
        
    except Exception as e:
        print(f"❌ Error processing {fn}: {e}")

if len(sampled_data) == 0:
    raise RuntimeError("No data loaded – check your dataset path or CSVs.")

# Clean the data - handle NaN, infinite values, and outliers
print("⚙️ Cleaning dataset - handling NaN, infinite values, and outliers")

# Replace NaN values with 0
data = sampled_data.fillna(0)

# Replace infinite values with large but finite values
data = data.replace([np.inf, -np.inf], np.nan).fillna(0)

# Handle extreme outliers by capping values
for col in data.select_dtypes(include=['float64', 'int64']).columns:
    # Cap extreme values at 99.9th percentile
    upper_limit = data[col].quantile(0.999)
    if upper_limit > 0:  # Only cap positive columns
        data.loc[data[col] > upper_limit, col] = upper_limit

print(f"✅ Final dataset: {len(data)} records with {len(data.columns)} features")

# ---- prepare data for model training ----
print("⚙️ Preparing data for model training")

# Identify the label column
print("  Identifying label column")
label_candidates = ["Label", "label", "CLASS", "class", "target", "Target"]
label_col = None

for candidate in label_candidates:
    if candidate in data.columns:
        label_col = candidate
        print(f"  Found label column: {label_col}")
        break

if label_col is None:
    # If no standard label column found, look for columns with these terms
    for col in data.columns:
        if any(term in col.lower() for term in ["label", "class", "target"]):
            label_col = col
            print(f"  Using column with label-like name: {label_col}")
            break

# If still no label column, use the last column
if label_col is None:
    label_col = data.columns[-1]
    print(f"  No label column identified, using last column: {label_col}")

# Store all column names
all_cols = list(data.columns)

# Convert categorical columns to numeric
print("  Converting categorical columns to numeric")
for col in data.columns:
    if col != label_col and data[col].dtype == 'object':
        # For categorical columns, convert to category codes
        data[col] = pd.Categorical(data[col]).codes

# More aggressive cleaning for numeric columns
print("  Additional cleaning of numeric data")
for col in data.select_dtypes(include=['float64', 'int64']).columns:
    if col != label_col:  # Skip the label column
        # Replace any remaining extreme values
        q1 = data[col].quantile(0.01)
        q3 = data[col].quantile(0.99)
        iqr = q3 - q1
        lower_bound = q1 - 3 * iqr
        upper_bound = q3 + 3 * iqr
        data.loc[data[col] < lower_bound, col] = lower_bound
        data.loc[data[col] > upper_bound, col] = upper_bound
        
        # Convert to float32 to reduce memory and potential overflow
        data[col] = data[col].astype('float32')

# Final check for any remaining problematic values
data = data.replace([np.inf, -np.inf], 0)
data = data.fillna(0)

# ---- split into X and y ----
# normalize labels
print("  Normalizing labels")
try:
    y = data[label_col].astype(str).str.upper()
    # Map various benign labels to 'Normal'
    benign_patterns = ["BENIGN", "NORMAL", "0"]
    y = y.apply(lambda x: "Normal" if any(pattern in x for pattern in benign_patterns) else "Attack")
    
    # Get all feature columns (everything except the label column)
    feat_cols = [col for col in all_cols if col != label_col]
    
    # Convert all features to numeric, handling errors
    X = data[feat_cols].apply(pd.to_numeric, errors='coerce').fillna(0)
    
    # Remove any constant columns that don't provide useful information
    const_cols = [col for col in X.columns if X[col].nunique() <= 1]
    if const_cols:
        print(f"  Removing {len(const_cols)} constant columns")
        X = X.drop(columns=const_cols)
        feat_cols = [col for col in feat_cols if col not in const_cols]
    
    print(f"✅ Final feature count: {len(feat_cols)}")
    print(f"✅ Class distribution: {y.value_counts().to_dict()}")
    
except Exception as e:
    print(f"❌ Error processing labels: {e}")
    print("  Falling back to simple X/y split")
    X = data.iloc[:, :-1]  # All columns except the last one
    y = data.iloc[:, -1]   # Last column as target
    print(f"✅ Using {X.shape[1]} features and {y.nunique()} classes")

# ---- scale and split ----
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

X_train, X_test, y_train, y_test = train_test_split(
    X_scaled, y, test_size=0.3, random_state=42
)

# ---- train and save ----
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

os.makedirs(MODEL_PATH, exist_ok=True)
joblib.dump(model,  os.path.join(MODEL_PATH, "model.pkl"))
joblib.dump(scaler, os.path.join(MODEL_PATH, "scaler.pkl"))

print("✅ Trained model + scaler saved to", MODEL_PATH)
