import pandas as pd
import pickle
import os
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.utils import resample

from feature_extraction import extract_features_with_reason

# Load dataset
data = pd.read_csv("dataset/final_dataset.csv")

# Clean
data = data.dropna()
data = data[data["url"].str.len() > 5]

# Show distribution
print("\n📊 Original Class Distribution:\n")
print(data["label"].value_counts())

# Balance dataset
df_legit = data[data.label == 0]
df_phish = data[data.label == 1]

df_phish_upsampled = resample(
    df_phish,
    replace=True,
    n_samples=len(df_legit),
    random_state=42
)

data = pd.concat([df_legit, df_phish_upsampled])

print("\n📊 Balanced Class Distribution:\n")
print(data["label"].value_counts())

# 🔥 IMPORTANT FIX → disable WHOIS
X = data["url"].apply(lambda x: extract_features_with_reason(x, use_whois=False)[0]).tolist()
y = data["label"]

# Split
X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

# Train
model = RandomForestClassifier(
    n_estimators=200,
    max_depth=15,
    n_jobs=-1,
    random_state=42
)

model.fit(X_train, y_train)

# Evaluate
y_pred = model.predict(X_test)

print("\n🔥 Model Accuracy:", round(accuracy_score(y_test, y_pred) * 100, 2), "%\n")
print("📊 Classification Report:\n", classification_report(y_test, y_pred))
print("📊 Confusion Matrix:\n", confusion_matrix(y_test, y_pred))

# Save
os.makedirs("model", exist_ok=True)

with open("model/model.pkl", "wb") as f:
    pickle.dump(model, f)

print("\n✅ Model trained and saved at model/model.pkl")