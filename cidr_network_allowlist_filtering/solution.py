"""Exercise 2: CIDR / Network Allowlist Filtering

Security posture monitoring requires flagging API calls initiated outside
authorized corporate egress ranges or private subnets.
"""

from collections import defaultdict
import ipaddress
import json
import logging
from typing import Any, Dict, List, Optional, Set, Tuple, Union

logger = logging.getLogger(__name__)


class UnauthorizedEgressResult(dict):
    """A dictionary mapping unique unapproved IPs to the set of actions they performed.

    Inherits from standard `dict` for full dictionary compatibility (e.g.
    `result[ip]`, `len(result)`, `result.items()`), while offering convenient
    helper methods for different caller preferences (e.g., sets of tuples,
    sets of unique IPs, or JSON-serializable dictionaries).
    """

    def unique_ips(self) -> Set[str]:
        """Returns the set of unique unapproved IP addresses."""
        return set(self.keys())

    def to_tuples(self) -> Set[Tuple[str, str]]:
        """Returns unauthorized egress events as a set of (client_ip, action) tuples."""
        tuples_set: Set[Tuple[str, str]] = set()
        for ip, actions in self.items():
            for action in actions:
                tuples_set.add((ip, action))
        return tuples_set

    def to_dict_lists(self) -> Dict[str, List[str]]:
        """Returns the mapping with actions sorted as lists for JSON serialization."""
        return {ip: sorted(list(actions)) for ip, actions in self.items()}


def parse_approved_cidrs(
    cidrs: List[str],
) -> Tuple[List[ipaddress.IPv4Network], List[ipaddress.IPv6Network]]:
    """Pre-parses and validates a list of CIDR strings into IPv4 and IPv6 network objects.

    Uses `strict=False` so CIDRs with host bits set (e.g., '192.168.1.50/24')
    are safely masked to their base subnet ('192.168.1.0/24'). Malformed CIDRs
    are defensively caught and skipped without crashing.
    """
    v4_networks: List[ipaddress.IPv4Network] = []
    v6_networks: List[ipaddress.IPv6Network] = []

    if not cidrs:
        return v4_networks, v6_networks

    for cidr in cidrs:
        if not isinstance(cidr, str):
            logger.warning("Skipping non-string CIDR entry: %r", cidr)
            continue
        clean_cidr = cidr.strip()
        if not clean_cidr:
            continue
        try:
            network = ipaddress.ip_network(clean_cidr, strict=False)
            if isinstance(network, ipaddress.IPv4Network):
                v4_networks.append(network)
            elif isinstance(network, ipaddress.IPv6Network):
                v6_networks.append(network)
        except (ValueError, TypeError) as exc:
            # Defensively handle malformed CIDR strings without crashing
            logger.warning("Ignoring malformed CIDR %r: %s", cidr, exc)

    return v4_networks, v6_networks


def is_ip_in_networks(
    ip_obj: Union[ipaddress.IPv4Address, ipaddress.IPv6Address],
    v4_networks: List[ipaddress.IPv4Network],
    v6_networks: List[ipaddress.IPv6Network],
) -> bool:
    """Checks whether an IP address belongs to any of the pre-parsed networks.

    Optimizes performance by checking only against networks matching the IP version.
    """
    if ip_obj.version == 4:
        return any(ip_obj in net for net in v4_networks)
    elif ip_obj.version == 6:
        return any(ip_obj in net for net in v6_networks)
    return False


def find_unauthorized_egress(
    log_entries: List[Dict[str, Any]],
    approved_cidrs: List[str],
) -> UnauthorizedEgressResult:
    """Validates log client IPs against approved CIDRs and detects unauthorized egress.

    Args:
        log_entries: List of log records containing 'client_ip' and 'action'.
        approved_cidrs: List of approved CIDR ranges (IPv4 and/or IPv6).

    Returns:
        UnauthorizedEgressResult (dict): A mapping of each unique unapproved IP
        to the set of actions it performed. Malformed IPs are gracefully ignored.
    """
    result = UnauthorizedEgressResult()

    if not log_entries:
        return result

    # 1. Pre-parse and partition approved CIDR ranges once for O(1) network math
    v4_networks, v6_networks = parse_approved_cidrs(approved_cidrs)

    # 2. Cache IP evaluation results to avoid redundant subnet calculations for repeated IPs
    approval_cache: Dict[str, bool] = {}

    for entry in log_entries:
        if not isinstance(entry, dict):
            logger.warning("Skipping non-dict log entry: %r", entry)
            continue

        raw_ip = entry.get("client_ip")
        if not isinstance(raw_ip, str):
            # Missing or non-string IP - gracefully skip without crashing
            continue

        ip_str = raw_ip.strip()
        if not ip_str:
            continue

        # Check memoized approval status if IP was already validated
        if ip_str in approval_cache:
            is_approved = approval_cache[ip_str]
        else:
            try:
                ip_obj = ipaddress.ip_address(ip_str)
                is_approved = is_ip_in_networks(ip_obj, v4_networks, v6_networks)
                approval_cache[ip_str] = is_approved
            except (ValueError, TypeError):
                # Defensively catch malformed IP strings without crashing
                logger.debug("Malformed IP string encountered: %r", raw_ip)
                continue

        # If IP is valid but not in any approved CIDR, record unauthorized action
        if not is_approved:
            action = entry.get("action", "UNKNOWN_ACTION")
            if ip_str not in result:
                result[ip_str] = set()
            result[ip_str].add(str(action))

    return result


# Sample dataset from the exercise prompt
sample_approved_cidrs = ["10.0.0.0/8", "192.168.1.0/24", "2001:db8::/32"]

sample_logs = [
    {"action": "DescribeSecret", "client_ip": "10.5.2.1"},  # Allowed (IPv4 private range)
    {"action": "DeleteBucket", "client_ip": "203.0.113.45"},  # Unauthorized (IPv4 external)
    {"action": "AssumeRole", "client_ip": "invalid-ip-string"},  # Malformed IP (gracefully ignored)
    {"action": "UpdatePolicy", "client_ip": "203.0.113.45"},  # Unauthorized (duplicate IP)
    {"action": "GetCallerIdentity", "client_ip": "2001:db8::100"},  # Allowed (IPv6 approved range)
    {"action": "ListUsers", "client_ip": "2607:f8b0:4005:805::200e"},  # Unauthorized (IPv6 external)
]


if __name__ == "__main__":
    print("=" * 70)
    print("Exercise 2: CIDR / Network Allowlist Filtering")
    print("=" * 70)
    print("\nApproved CIDRs:")
    for cidr in sample_approved_cidrs:
        print(f"  - {cidr}")

    print("\nProcessing sample logs...")
    alerts = find_unauthorized_egress(sample_logs, sample_approved_cidrs)

    print(f"\nDetected {len(alerts)} unique unapproved IP(s):\n")
    for ip, actions in alerts.items():
        print(f"  [!] IP: {ip}")
        print(f"      Actions ({len(actions)}): {', '.join(sorted(actions))}")

    print("\nAlternative output formats:")
    print("  Unique IPs set :", alerts.unique_ips())
    print("  Tuples set     :", alerts.to_tuples())
    print("  JSON format    :", json.dumps(alerts.to_dict_lists(), indent=2))
