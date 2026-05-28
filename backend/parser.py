# backend/parser.py
# Parses Apache/Nginx access log files into structured data.
#
# Expected log format (Combined Log Format):
# 192.168.1.1 - - [15/May/2024:02:13:45 +0000] "GET /login HTTP/1.1" 401 512

import re
import pandas as pd

# Compiled regex pattern for Apache Combined Log Format.
# Each group in () captures one field from the log line.
LOG_PATTERN = re.compile(
    r'(\d+\.\d+\.\d+\.\d+)'   # group 1: IP address
    r' - - '
    r'\[(.+?)\]'               # group 2: timestamp
    r' "'
    r'(\w+)'                   # group 3: HTTP method (GET, POST, etc.)
    r' (\S+)'                  # group 4: request path (/login, /admin, etc.)
    r' HTTP/\d\.\d"'
    r' (\d+)'                  # group 5: HTTP status code
    r' (\d+)'                  # group 6: response size in bytes
)


def parse_log_file(filepath):
    """
    Reads a log file line by line and extracts structured fields from each line.

    Silently skips lines that don't match the expected format.

    Args:
        filepath: path to the log file (string)

    Returns:
        A list of dictionaries, one per valid log line, with keys:
        ip, timestamp, method, path, status_code, bytes
    """
    entries = []

    with open(filepath, 'r') as f:
        for line in f:
            match = LOG_PATTERN.match(line.strip())
            if match:
                entries.append({
                    'ip':          match.group(1),
                    'timestamp':   match.group(2),
                    'method':      match.group(3),
                    'path':        match.group(4),
                    'status_code': int(match.group(5)),
                    'bytes':       int(match.group(6)),
                })

    return entries


def load_log_dataframe(filepath):
    """
    Parses a log file and returns a pandas DataFrame with a proper datetime column.

    Builds on parse_log_file() by converting the raw timestamp string into a
    real datetime object that pandas can filter and group by time.

    Args:
        filepath: path to the log file (string)

    Returns:
        A pandas DataFrame with columns:
        ip, timestamp (datetime), method, path, status_code, bytes
    """
    entries = parse_log_file(filepath)
    df = pd.DataFrame(entries)
    df['timestamp'] = pd.to_datetime(df['timestamp'], format='%d/%b/%Y:%H:%M:%S %z')
    return df


if __name__ == '__main__':
    entries = parse_log_file('data/sample.log')
    for entry in entries:
        print(entry)