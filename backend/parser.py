import re
import pandas as pd

LOG_PATTERN = re.compile(
    r'(\d+\.\d+\.\d+\.\d+)'   # IP address
    r' - - '
    r'\[(.+?)\]'               # timestamp
    r' "'
    r'(\w+)'                   # HTTP method 
    r' (\S+)'                  # path 
    r' HTTP/\d\.\d"'
    r' (\d+)'                  # status code
    r' (\d+)'                  # bytes
)

def parse_log_file(filepath):
    results = []

    with open(filepath, 'r') as f:
        for line in f:
            match = LOG_PATTERN.match(line.strip())
            if match:
                results.append({
                    'ip':          match.group(1),
                    'timestamp':   match.group(2),
                    'method':      match.group(3),
                    'path':        match.group(4),
                    'status_code': int(match.group(5)),
                    'bytes':       int(match.group(6)),
                })

    return results

def load_log_dataframe(filepath):
    enteries = parse_log_file(filepath)
    df = pd.DataFrame(enteries)
    df['timestamp'] = pd.to_datetime(df['timestamp'], format='%d/%b/%Y:%H:%M:%S %z')
    return df


if __name__ == '__main__':
    enteries = parse_log_file('data/sample.log')
    for entry in enteries:
        print(entry)