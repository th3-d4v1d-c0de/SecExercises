# Exercise 2: CIDR / Network Allowlist Filtering

## Context

Security posture monitoring requires flagging API calls initiated outside authorized corporate egress ranges or private subnets. In modern hybrid-cloud environments, services communicate across both IPv4 and IPv6 networks. Threat actors or compromised credentials may initiate requests from unvetted public internet endpoints, misconfigured VPCs, or third-party networks.

To protect sensitive cloud resources, security teams monitor audit logs and ensure that sensitive API actions originate strictly from designated CIDR blocks.

---

## Problem Statement

Write a Python function `find_unauthorized_egress(log_entries, approved_cidrs)` that:

1. **Validates each `client_ip`** against the list of `approved_cidrs` (which may contain both IPv4 and IPv6 strings).
2. **Gracefully handles malformed IP strings** without crashing (via defensive exception handling).
3. **Returns a set of unique unapproved IPs and the actions they performed**.

### Input Structure

```python
approved_cidrs = ["10.0.0.0/8", "192.168.1.0/24", "2001:db8::/32"]

logs = [
    {"action": "DescribeSecret", "client_ip": "10.5.2.1"},       # Allowed
    {"action": "DeleteBucket", "client_ip": "203.0.113.45"},     # Unauthorized
    {"action": "AssumeRole", "client_ip": "invalid-ip-string"},  # Malformed
    {"action": "UpdatePolicy", "client_ip": "203.0.113.45"},     # Unauthorized (duplicate IP)
]
```

### Expected Output Format

The function returns an `UnauthorizedEgressResult` mapping each unique unapproved IP to the set of actions it performed:

```python
{
    "203.0.113.45": {"DeleteBucket", "UpdatePolicy"}
}
```

Because `UnauthorizedEgressResult` inherits from Python's standard `dict`, it also provides helper methods for different caller needs:

- **Unique unapproved IPs:** `result.unique_ips()` $\rightarrow$ `{"203.0.113.45"}`
- **Set of tuples:** `result.to_tuples()` $\rightarrow$ `{("203.0.113.45", "DeleteBucket"), ("203.0.113.45", "UpdatePolicy")}`
- **JSON-serializable lists:** `result.to_dict_lists()` $\rightarrow$ `{"203.0.113.45": ["DeleteBucket", "UpdatePolicy"]}`

---

## Technical Concepts Tested

1. **Python Standard Library `ipaddress`**:
   - `ipaddress.ip_address(ip_str)` for converting IPv4 and IPv6 string addresses into address objects.
   - `ipaddress.ip_network(cidr, strict=False)` for CIDR parsing, handling subnets with host bits set (e.g., `192.168.1.50/24`).
   - Testing membership with `ip_obj in network_obj`.

2. **Defensive Exception Handling**:
   - Catching `(ValueError, TypeError)` when parsing `client_ip` strings to handle malformed inputs (e.g. `'invalid-ip-string'`, out-of-range octets, `None`, missing keys) without crashing.
   - Safely skipping malformed CIDR strings in `approved_cidrs`.

3. **Performance & Data Filtering**:
   - **CIDR Pre-compilation**: Pre-parsing CIDR strings into `ipaddress` network objects once outside the log loop, rather than re-parsing CIDRs for every log record.
   - **Version Partitioning**: Partitioning networks into IPv4 and IPv6 lists so IPv4 addresses are only checked against IPv4 subnets.
   - **Memoization / Caching**: Caching approval checks by IP string to achieve $O(1)$ lookup for duplicate IPs across large log volumes.

---

## Running the Code

From the repository root, you can use the `Makefile`:

```bash
# Run unit tests for Exercise 2
make test-ex2

# Run the solution script on sample logs
make run-ex2

# Run all exercises tests
make test
```

Or run Python directly:

```bash
python3 cidr_network_allowlist_filtering/solution.py
python3 -m unittest cidr_network_allowlist_filtering/test_solution.py
```
