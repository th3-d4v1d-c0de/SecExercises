from collections import defaultdict, deque
from datetime import datetime, timezone
import json
from typing import Any, Dict, List, Optional


def parse_timestamp(ts: str) -> datetime:
    """Parses ISO-8601 timestamps, standardizing UTC representations."""
    # Handle 'Z' suffix for Python versions before 3.11
    normalized = ts.replace("Z", "+00:00")
    dt = datetime.fromisoformat(normalized)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def is_failure(event: Dict[str, Any]) -> bool:
    """Returns True if the event has an error code indicating failure."""
    code = event.get("errorCode")
    return code is not None and str(code).strip() != ""


def detect_compromised_identities(
    log_events: List[Dict[str, Any]],
    threshold: int = 3,
    time_window_seconds: int = 300,
) -> List[Dict[str, Any]]:
    """
    Detects identities that have >= threshold failures followed by at least
    one successful API call within time_window_seconds.
    """
    if not log_events or threshold <= 0:
        return []

    # 1. Sort events chronologically to guarantee accurate window comparisons
    sorted_events = sorted(log_events, key=lambda e: parse_timestamp(e["timestamp"]))

    # 2. Group events by identity
    events_by_identity: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for event in sorted_events:
        identity = event.get("identity")
        if identity:
            events_by_identity[identity].append(event)

    alerts: List[Dict[str, Any]] = []

    # 3. Sliding window analysis per identity
    for identity, events in events_by_identity.items():
        # NOTE: We use `collections.deque` (Double-Ended Queue) instead of a standard list.
        # A list's `list.pop(0)` takes O(N) time because it shifts every remaining element in memory.
        # `deque.popleft()` removes expired elements from the front in O(1) constant time,
        # which is essential for efficient sliding window algorithms processing large log streams.
        recent_failures: deque = deque()

        for event in events:
            curr_time = parse_timestamp(event["timestamp"])

            if is_failure(event):
                recent_failures.append(event)
            else:
                # It's a success: prune failures that fell outside the time window
                cutoff_time = curr_time.timestamp() - time_window_seconds
                while recent_failures and parse_timestamp(recent_failures[0]["timestamp"]).timestamp() < cutoff_time:
                    recent_failures.popleft()

                # Check if we have enough failures within the window
                if len(recent_failures) >= threshold:
                    first_failure_event = recent_failures[0]
                    alerts.append(
                        {
                            "identity": identity,
                            "failed_count": len(recent_failures),
                            "first_failure": first_failure_event["timestamp"],
                            "first_success": event["timestamp"],
                            "source_ip": event.get("sourceIP") or first_failure_event.get("sourceIP"),
                        }
                    )
                    # Reset failure queue after alerting to avoid re-triggering for consecutive successes
                    recent_failures.clear()

    return alerts


sample_logs = [
    # Normal user traffic
    {
        "timestamp": "2026-10-20T17:00:00Z",
        "identity": "user_alice",
        "eventName": "DescribeInstances",
        "errorCode": None,
        "sourceIP": "10.0.1.5",
    },
    {
        "timestamp": "2026-10-20T17:01:00Z",
        "identity": "user_alice",
        "eventName": "ListBuckets",
        "errorCode": None,
        "sourceIP": "10.0.1.5",
    },
    # Suspicious user traffic (3 failures followed by success within 5 mins)
    {
        "timestamp": "2026-10-20T17:02:00Z",
        "identity": "user_bob",
        "eventName": "CreateUser",
        "errorCode": "AccessDenied",
        "sourceIP": "198.51.100.24",
    },
    {
        "timestamp": "2026-10-20T17:03:10Z",
        "identity": "user_bob",
        "eventName": "AttachRolePolicy",
        "errorCode": "AccessDenied",
        "sourceIP": "198.51.100.24",
    },
    {
        "timestamp": "2026-10-20T17:04:00Z",
        "identity": "user_bob",
        "eventName": "PutBucketPolicy",
        "errorCode": "AccessDenied",
        "sourceIP": "198.51.100.24",
    },
    {
        "timestamp": "2026-10-20T17:05:30Z",
        "identity": "user_bob",
        "eventName": "GetCallerIdentity",
        "errorCode": None,
        "sourceIP": "198.51.100.24",
    },
    # User with multiple failures, but NO subsequent success (not suspicious under this rule)
    {
        "timestamp": "2026-10-20T17:00:00Z",
        "identity": "user_charlie",
        "eventName": "ListSecrets",
        "errorCode": "AccessDenied",
        "sourceIP": "198.51.100.99",
    },
    {
        "timestamp": "2026-10-20T17:01:00Z",
        "identity": "user_charlie",
        "eventName": "DescribeKeys",
        "errorCode": "AccessDenied",
        "sourceIP": "198.51.100.99",
    },
    {
        "timestamp": "2026-10-20T17:02:00Z",
        "identity": "user_charlie",
        "eventName": "GetSecretValue",
        "errorCode": "AccessDenied",
        "sourceIP": "198.51.100.99",
    },
]


if __name__ == "__main__":
    results = detect_compromised_identities(sample_logs)
    print("Detected alerts:")
    print(json.dumps(results, indent=2))
