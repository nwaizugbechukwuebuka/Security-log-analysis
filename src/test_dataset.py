import pandas as pd

df = pd.read_csv("data/sample_security_logs.csv")

print(df.head())
print("\nDataset shape:", df.shape)
print("\nMissing values:\n", df.isnull().sum())