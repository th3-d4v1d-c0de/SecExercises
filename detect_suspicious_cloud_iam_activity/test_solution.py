import os
import sys
import unittest

# Ensure module is found regardless of where the test is run from
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from solution import detect_compromised_identities, sample_logs


class TestDetectCompromisedIdentities(unittest.TestCase):

    def test_sample_logs(self):
        alerts = detect_compromised_identities(sample_logs, threshold=3, time_window_seconds=300)
        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        self.assertEqual(alert["identity"], "user_bob")
        self.assertEqual(alert["failed_count"], 3)
        self.assertEqual(alert["first_failure"], "2026-10-20T17:02:00Z")
        self.assertEqual(alert["first_success"], "2026-10-20T17:05:30Z")
        self.assertEqual(alert["source_ip"], "198.51.100.24")

    def test_empty_logs(self):
        self.assertEqual(detect_compromised_identities([]), [])

    def test_out_of_order_logs(self):
        # Reverse Bob's logs to test out-of-order arrival
        bob_logs = [e for e in sample_logs if e["identity"] == "user_bob"]
        reversed_logs = list(reversed(bob_logs))
        alerts = detect_compromised_identities(reversed_logs, threshold=3, time_window_seconds=300)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["identity"], "user_bob")

    def test_window_expiration(self):
        # 3 failures, but the first failure occurred 600s before the success
        logs = [
            {"timestamp": "2026-10-20T17:00:00Z", "identity": "user_expired", "eventName": "A", "errorCode": "AccessDenied", "sourceIP": "1.1.1.1"},
            {"timestamp": "2026-10-20T17:08:00Z", "identity": "user_expired", "eventName": "B", "errorCode": "AccessDenied", "sourceIP": "1.1.1.1"},
            {"timestamp": "2026-10-20T17:09:00Z", "identity": "user_expired", "eventName": "C", "errorCode": "AccessDenied", "sourceIP": "1.1.1.1"},
            # Only 2 failures within 300s of 17:10:00 (17:08 and 17:09). 17:00 is outside window.
            {"timestamp": "2026-10-20T17:10:00Z", "identity": "user_expired", "eventName": "D", "errorCode": None, "sourceIP": "1.1.1.1"},
        ]
        alerts = detect_compromised_identities(logs, threshold=3, time_window_seconds=300)
        self.assertEqual(len(alerts), 0)

    def test_no_success(self):
        charlie_logs = [e for e in sample_logs if e["identity"] == "user_charlie"]
        alerts = detect_compromised_identities(charlie_logs, threshold=3, time_window_seconds=300)
        self.assertEqual(len(alerts), 0)


if __name__ == "__main__":
    unittest.main()
