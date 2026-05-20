import sys
sys.path.append('backend')

from parser import load_log_dataframe
import matplotlib.pyplot as plt

# Load the data
df = load_log_dataframe('data/sample.log')

print(f"Total requests: {len(df)}")
print(f"Time range: {df['timestamp'].min()} to {df['timestamp'].max()}")
print(f"Unique IPs: {df['ip'].nunique()}")

# Extract the hour from each timestamp
df['hour'] = df['timestamp'].dt.hour

# Count requests per hour
requests_per_hour = df.groupby('hour').size()

print("\n=== REQUESTS PER HOUR ===")
print(requests_per_hour)

print(f"\nBusiest hour:  {requests_per_hour.idxmax()}:00 ({requests_per_hour.max()} requests)")
print(f"Quietest hour: {requests_per_hour.idxmin()}:00 ({requests_per_hour.min()} requests)")

# Plot requests per hour
plt.figure(figsize=(12, 5))
bars = plt.bar(requests_per_hour.index, requests_per_hour.values, color='steelblue')

# Highlight suspicious off-hours (midnight to 6am) in red
for bar, hour in zip(bars, requests_per_hour.index):
    if hour < 6:
        bar.set_color('crimson')

plt.title('Requests Per Hour — Log Sentinel EDA')
plt.xlabel('Hour of Day')
plt.ylabel('Number of Requests')
plt.xticks(range(0, 24))
plt.tight_layout()
plt.savefig('data/requests_per_hour.png')
plt.show()

print("\nChart saved to data/requests_per_hour.png")