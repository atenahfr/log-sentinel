import sys
sys.path.append('backend')

import unittest
import pandas as pd
from datetime import datetime, timezone
from detector import detect_brute_force, detect_404_spike, detect_500_spike


def make_test_df(rows):
    """
    Helper function — builds a small DataFrame from a list of rows.
    This lets us create controlled test data instead of using the real log file.
    
    Args:
        rows: list of dicts with keys: ip, timestamp, method, path, status_code, bytes
    
    Returns:
        A pandas DataFrame with a proper datetime timestamp column
    """
    df = pd.DataFrame(rows)
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    return df


class TestBruteForceDetector(unittest.TestCase):
    """Tests for detect_brute_force()"""

    def test_flags_ip_over_threshold(self):
        """An IP with more failed logins than the threshold should be flagged"""
        rows = [
            {'ip': '1.2.3.4', 'timestamp': '2024-01-01 02:00:00+00:00',
             'method': 'GET', 'path': '/login', 'status_code': 401, 'bytes': 512}
        ] * 15  # 15 failed logins — over default threshold of 10

        df = make_test_df(rows)
        result = detect_brute_force(df, threshold=10)

        self.assertEqual(len(result), 1)           # exactly 1 IP flagged
        self.assertEqual(result.iloc[0]['ip'], '1.2.3.4')
        self.assertEqual(result.iloc[0]['anomaly_type'], 'brute_force')

    def test_does_not_flag_ip_under_threshold(self):
        """An IP with fewer failed logins than the threshold should NOT be flagged"""
        rows = [
            {'ip': '1.2.3.4', 'timestamp': '2024-01-01 02:00:00+00:00',
             'method': 'GET', 'path': '/login', 'status_code': 401, 'bytes': 512}
        ] * 5  # only 5 failed logins — under threshold of 10

        df = make_test_df(rows)
        result = detect_brute_force(df, threshold=10)

        self.assertEqual(len(result), 0)  # nothing should be flagged

    def test_only_counts_401s_on_login(self):
        """Successful logins (200) should not count toward brute force"""
        rows = [
            {'ip': '1.2.3.4', 'timestamp': '2024-01-01 02:00:00+00:00',
             'method': 'GET', 'path': '/login', 'status_code': 200, 'bytes': 512}
        ] * 15  # 15 successful logins — should NOT be flagged

        df = make_test_df(rows)
        result = detect_brute_force(df, threshold=10)

        self.assertEqual(len(result), 0)

    def test_explanation_is_generated(self):
        """Flagged IPs should have a non-empty explanation"""
        rows = [
            {'ip': '1.2.3.4', 'timestamp': '2024-01-01 02:00:00+00:00',
             'method': 'GET', 'path': '/login', 'status_code': 401, 'bytes': 512}
        ] * 15

        df = make_test_df(rows)
        result = detect_brute_force(df, threshold=10)

        self.assertIn('explanation', result.columns)
        self.assertTrue(len(result.iloc[0]['explanation']) > 0)


class TestSpikeDetectors(unittest.TestCase):
    """Tests for detect_404_spike() and detect_500_spike()"""

    def test_404_spike_flags_over_threshold(self):
        """An IP generating more 404s than threshold should be flagged"""
        rows = [
            {'ip': '5.6.7.8', 'timestamp': '2024-01-01 03:00:00+00:00',
             'method': 'GET', 'path': '/admin', 'status_code': 404, 'bytes': 256}
        ] * 12

        df = make_test_df(rows)
        result = detect_404_spike(df, threshold=10)

        self.assertEqual(len(result), 1)
        self.assertEqual(result.iloc[0]['ip'], '5.6.7.8')

    def test_404_spike_ignores_200s(self):
        """Normal 200 responses should not trigger 404 spike detection"""
        rows = [
            {'ip': '5.6.7.8', 'timestamp': '2024-01-01 03:00:00+00:00',
             'method': 'GET', 'path': '/index.html', 'status_code': 200, 'bytes': 2048}
        ] * 12

        df = make_test_df(rows)
        result = detect_404_spike(df, threshold=10)

        self.assertEqual(len(result), 0)

    def test_500_spike_flags_over_threshold(self):
        """An IP generating more 500s than threshold should be flagged"""
        rows = [
            {'ip': '9.10.11.12', 'timestamp': '2024-01-01 14:00:00+00:00',
             'method': 'POST', 'path': '/api/upload', 'status_code': 500, 'bytes': 128}
        ] * 8

        df = make_test_df(rows)
        result = detect_500_spike(df, threshold=5)

        self.assertEqual(len(result), 1)
        self.assertEqual(result.iloc[0]['ip'], '9.10.11.12')


if __name__ == '__main__':
    unittest.main(verbosity=2)