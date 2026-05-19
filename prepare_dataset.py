import pandas as pd

def get_url_column(df):
    for col in df.columns:
        if "url" in col.lower():
            return df[col]
    return df.iloc[:, 0]

# Load datasets
benign1 = pd.read_csv("dataset/Benign_list_big_final.csv")
benign2 = pd.read_csv("dataset/online-valid.csv")
benign3 = pd.read_csv("dataset/legitimate.csv")

phishing = pd.read_csv("dataset/phishing_urls.csv")
phishing.columns = ["url"]

# Extract URL
benign1 = get_url_column(benign1).to_frame(name="url")
benign2 = get_url_column(benign2).to_frame(name="url")
benign3 = get_url_column(benign3).to_frame(name="url")

# Add labels
benign1["label"] = 0
benign2["label"] = 0
benign3["label"] = 0
phishing["label"] = 1

# Combine
data = pd.concat([benign1, benign2, benign3, phishing], ignore_index=True)

# Clean FIRST
data = data.drop_duplicates()
data = data[data["url"].notnull()]
data = data[data["url"].str.len() > 5]

# 🔥 NOW UPSAMPLE (AFTER CLEANING)
df_legit = data[data.label == 0]
df_phish = data[data.label == 1]

df_phish = pd.concat([df_phish]*2000, ignore_index=True)

data = pd.concat([df_legit, df_phish])

# Save
data.to_csv("dataset/final_dataset.csv", index=False)

print("\nFinal dataset:\n", data["label"].value_counts())