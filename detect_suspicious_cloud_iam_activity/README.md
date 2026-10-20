# Challenge: Detect Suspicious Cloud IAM Activity

## Context

An attacker acquired a leaked AWS API key. Before attempting privilege escalation or exfiltration, attackers typically follow a specific sequence:

1. Multiple reconnaissance or unauthorized calls that trigger `AccessDenied`.
2. A subsequent successful API call (`errorCode` is null/empty) within a short time window once they discover valid permissions.

---

## Problem Statement

Write a Python function `detect_compromised_identities(log_events, threshold=3, time_window_seconds=300)` that accepts a list of JSON-like log entries and returns a list of suspicious identities.

An identity is considered suspicious if:
- The same identity experiences $\ge$ `threshold` failed calls (`errorCode` is not null).
- Followed by at least one successful call (`errorCode` is null or missing).
- All occurring within a sliding window of `time_window_seconds` (default: 300 seconds / 5 minutes).

### Expected Output Format

Your function should return a list of dictionaries, one per detected alert:

```json
[
    {
        "identity": "arn:aws:iam::123456789012:user/dev-test",
        "failed_count": 3,
        "first_failure": "2026-10-20T17:00:00Z",
        "first_success": "2026-10-20T17:04:15Z",
        "source_ip": "198.51.100.24"
    }
]
```

---

## Tips & Considerations

1. **Parse ISO timestamps into `datetime` objects**:
   - `datetime.fromisoformat(ts.replace("Z", "+00:00"))` handles UTC ISO-8601 strings across Python versions.
2. **Sort events chronologically**:
   - Logs may arrive out-of-order; sorting by timestamp ensures accurate sliding window evaluation.
3. **Group events**:
   - Group events by identity (and optionally `sourceIP` depending on requirements).
4. **Sliding Window Logic**:
   - Track failed events within the window leading up to a success.
