import os
import sys
import unittest

# Ensure module is importable regardless of working directory
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from solution import (
    UnauthorizedEgressResult,
    find_unauthorized_egress,
    parse_approved_cidrs,
    sample_approved_cidrs,
    sample_logs,
)


class TestFindUnauthorizedEgress(unittest.TestCase):

    def test_prompt_sample_dataset(self):
        """Validates the exact example given in the problem prompt."""
        approved_cidrs = ["10.0.0.0/8", "192.168.1.0/24", "2001:db8::/32"]
        logs = [
            {"action": "DescribeSecret", "client_ip": "10.5.2.1"},  # Allowed
            {"action": "DeleteBucket", "client_ip": "203.0.113.45"},  # Unauthorized
            {"action": "AssumeRole", "client_ip": "invalid-ip-string"},  # Malformed
            {"action": "UpdatePolicy", "client_ip": "203.0.113.45"},  # Unauthorized (duplicate IP)
        ]

        result = find_unauthorized_egress(logs, approved_cidrs)

        # 203.0.113.45 should be the only detected unapproved IP
        self.assertIn("203.0.113.45", result)
        self.assertEqual(len(result), 1)

        # Actions performed by the unapproved IP
        expected_actions = {"DeleteBucket", "UpdatePolicy"}
        self.assertEqual(result["203.0.113.45"], expected_actions)

        # Allowed and malformed IPs must not be in the output
        self.assertNotIn("10.5.2.1", result)
        self.assertNotIn("invalid-ip-string", result)

        # Verify helper methods
        self.assertEqual(result.unique_ips(), {"203.0.113.45"})
        self.assertEqual(
            result.to_tuples(),
            {("203.0.113.45", "DeleteBucket"), ("203.0.113.45", "UpdatePolicy")},
        )

    def test_ipv6_approved_and_unapproved(self):
        """Tests IPv6 validation against IPv6 CIDR ranges."""
        approved_cidrs = ["2001:db8::/32"]
        logs = [
            {"action": "ActionA", "client_ip": "2001:db8::1"},  # Allowed
            {"action": "ActionB", "client_ip": "2001:db8:ffff::1"},  # Allowed
            {"action": "ActionC", "client_ip": "2607:f8b0:4005:805::200e"},  # Unauthorized
        ]

        result = find_unauthorized_egress(logs, approved_cidrs)
        self.assertEqual(len(result), 1)
        self.assertIn("2607:f8b0:4005:805::200e", result)
        self.assertEqual(result["2607:f8b0:4005:805::200e"], {"ActionC"})

    def test_malformed_ips_handled_gracefully(self):
        """Ensures non-parseable and invalid IP strings never crash the function."""
        approved_cidrs = ["10.0.0.0/8"]
        malformed_logs = [
            {"action": "Call1", "client_ip": "999.999.999.999"},
            {"action": "Call2", "client_ip": "not_an_ip"},
            {"action": "Call3", "client_ip": "1.2.3"},
            {"action": "Call4", "client_ip": ""},
            {"action": "Call5", "client_ip": "2001:xyz::1"},
            {"action": "Call6", "client_ip": None},
            {"action": "Call7"},  # Missing client_ip key
        ]

        result = find_unauthorized_egress(malformed_logs, approved_cidrs)
        self.assertEqual(result, {})

    def test_malformed_cidrs_handled_gracefully(self):
        """Ensures invalid CIDRs in approved_cidrs are ignored without crashing."""
        approved_cidrs = ["invalid-cidr", "10.0.0.0/8", "999.0.0.0/8", None, ""]
        logs = [
            {"action": "CallA", "client_ip": "10.1.2.3"},  # Allowed by 10.0.0.0/8
            {"action": "CallB", "client_ip": "172.16.0.1"},  # Unauthorized
        ]

        result = find_unauthorized_egress(logs, approved_cidrs)
        self.assertNotIn("10.1.2.3", result)
        self.assertIn("172.16.0.1", result)

    def test_cidr_with_host_bits_set(self):
        """Ensures CIDRs with host bits (e.g. 192.168.1.50/24) are masked properly."""
        approved_cidrs = ["192.168.1.50/24"]  # strict=False should mask to 192.168.1.0/24
        logs = [
            {"action": "Action1", "client_ip": "192.168.1.200"},  # Allowed
            {"action": "Action2", "client_ip": "192.168.2.200"},  # Unauthorized
        ]

        result = find_unauthorized_egress(logs, approved_cidrs)
        self.assertNotIn("192.168.1.200", result)
        self.assertIn("192.168.2.200", result)

    def test_empty_logs_and_empty_cidrs(self):
        """Tests behavior when either logs or approved_cidrs are empty."""
        # Empty logs should yield an empty result
        self.assertEqual(find_unauthorized_egress([], ["10.0.0.0/8"]), {})

        # Empty approved_cidrs means all valid IPs are unauthorized
        logs = [{"action": "Test", "client_ip": "10.0.0.1"}]
        result = find_unauthorized_egress(logs, [])
        self.assertEqual(result, {"10.0.0.1": {"Test"}})

    def test_duplicate_actions_deduplication(self):
        """Verifies that duplicate actions by the same unapproved IP are deduplicated."""
        logs = [
            {"action": "DeleteBucket", "client_ip": "203.0.113.45"},
            {"action": "DeleteBucket", "client_ip": "203.0.113.45"},
            {"action": "DeleteBucket", "client_ip": "203.0.113.45"},
        ]
        result = find_unauthorized_egress(logs, ["10.0.0.0/8"])
        self.assertEqual(result["203.0.113.45"], {"DeleteBucket"})

    def test_ip_with_whitespace(self):
        """Checks that whitespace around valid IP strings is trimmed cleanly."""
        logs = [
            {"action": "AllowedAction", "client_ip": "  10.5.2.1  \n"},
            {"action": "UnapprovedAction", "client_ip": "\t203.0.113.45 "},
        ]
        result = find_unauthorized_egress(logs, ["10.0.0.0/8"])
        self.assertNotIn("10.5.2.1", result)
        self.assertIn("203.0.113.45", result)


if __name__ == "__main__":
    unittest.main()
