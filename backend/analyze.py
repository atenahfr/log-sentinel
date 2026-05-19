from parser import load_log_dataframe

df = load_log_dataframe('data/sample.log')

print("=== FIRST 5 ROWS ===")
print(df.head())


print("\n=== DATAFRAME INFO ===")
print(df.info())

print("\n=== BASIC STATS ===")
print(df.describe())

print("\n=== MOST COMMON IP ===")
print(df['ip'].value_counts().head())

print("\n=== MOST COMMON STATUS CODE ===")
print(df['status_code'].value_counts())

print("\n=== MOST COMMON PATH ===")
print(df['path'].value_counts().head())