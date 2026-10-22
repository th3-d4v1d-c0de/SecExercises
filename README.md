# Security Engineering Coding Exercises (`SecExercises`)

A collection of hands-on security engineering, detection engineering, and cloud security coding challenges implemented in Python using the Python standard library.

Each exercise simulates real-world security engineering problems—ranging from identity threat detection and sliding-window event correlation to network posture monitoring and defensive log ingestion.

---

## Exercise Catalog

| # | Exercise | Focus Areas | Key Python Concepts |
|---|----------|-------------|---------------------|
| **1** | [Detect Suspicious Cloud IAM Activity](./detect_suspicious_cloud_iam_activity) | Threat Detection, Cloud IAM, Reconnaissance-to-Exploit Correlation | `collections.deque`, sliding window algorithms, ISO-8601 parsing |
| **2** | [CIDR / Network Allowlist Filtering](./cidr_network_allowlist_filtering) | Security Posture Monitoring, Egress Control, Network Allowlisting | Standard library `ipaddress`, IPv4 & IPv6, defensive exception handling |

---

### Exercise 1: Detect Suspicious Cloud IAM Activity
- **Directory:** [`detect_suspicious_cloud_iam_activity/`](./detect_suspicious_cloud_iam_activity)
- **Scenario:** Attackers with leaked API keys often perform reconnaissance generating multiple `AccessDenied` errors before hitting an API call they have permissions for.
- **Goal:** Implement `detect_compromised_identities(log_events, threshold, time_window_seconds)` to flag identities experiencing $\ge$ `threshold` failures followed by a success within a sliding time window.
- **Highlights:** Utilizes `collections.deque` for $O(1)$ eviction of expired log events instead of $O(N)$ list shifts.

### Exercise 2: CIDR / Network Allowlist Filtering
- **Directory:** [`cidr_network_allowlist_filtering/`](./cidr_network_allowlist_filtering)
- **Scenario:** Posture monitoring requires identifying API calls initiated from unauthorized public IPs or unapproved private subnets.
- **Goal:** Implement `find_unauthorized_egress(log_entries, approved_cidrs)` to validate client IPs against approved IPv4/IPv6 CIDRs and return unique unapproved IPs with their actions.
- **Highlights:** Uses `ipaddress` with `strict=False` CIDR normalization, defensive handling of malformed IP strings without crashing, and approval caching for high-volume logs.

---

## Repository Structure

```text
.
├── Makefile                                # Root Makefile (orchestrates all exercises)
├── README.md                               # Main repository documentation
├── detect_suspicious_cloud_iam_activity/   # Exercise 1
│   ├── Makefile                            # Exercise 1 standalone Makefile
│   ├── README.md                           # Problem specification & walkthrough
│   ├── deque_explanation.md                # In-depth guide on deque for sliding windows
│   ├── samples_logs.txt                    # Raw sample audit logs
│   ├── solution.py                         # Solution implementation
│   └── test_solution.py                    # Unit tests (unittest)
└── cidr_network_allowlist_filtering/       # Exercise 2
    ├── Makefile                            # Exercise 2 standalone Makefile
    ├── README.md                           # Problem specification & walkthrough
    ├── sample_logs.json                    # Sample logs & CIDRs dataset
    ├── solution.py                         # Solution implementation
    └── test_solution.py                    # Unit tests (unittest)
```

---

## Getting Started

### Prerequisites

- **Python 3.9+** (no external packages required; uses strictly the Python standard library)
- **Make** (optional, but recommended for running tasks)

---

## Running Exercises

You can execute exercises either from the repository root or independently within each exercise directory.

### 1. From the Repository Root

```bash
# Run all unit tests across all exercises
make test

# Run all exercise solution scripts on sample data
make run

# Run both all tests and solutions
make all

# Run specific exercises
make test-ex1   # Test Exercise 1
make run-ex1    # Run Exercise 1
make test-ex2   # Test Exercise 2
make run-ex2    # Run Exercise 2

# Clean up Python __pycache__ and bytecode
make clean
```

### 2. From Within an Exercise Directory

Each exercise contains its own standalone `Makefile`:

```bash
# Exercise 1:
cd detect_suspicious_cloud_iam_activity
make test
make run

# Exercise 2:
cd ../cidr_network_allowlist_filtering
make test
make run
```
