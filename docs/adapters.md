# Adapter input contracts

`infra-report` never calls a cloud API. Each adapter parses the JSON a scanner
already produced, which is what makes the whole pipeline runnable — and
testable — with no credentials in the room.

Every adapter is tolerant in one direction only: unknown keys are ignored, a
missing array yields no findings, and malformed JSON is an error. If a scanner
adds a field, nothing breaks.

Fixtures for all ten formats live in
[`internal/adapter/testdata/`](../internal/adapter/testdata) and are the same
files the example tenant in [`examples/acme/in/`](../examples/acme/in) uses.

---

## `cost-export` → cost block

Two months of service-level spend. Emits **no findings**; it fills the typed
cost summary that the "largest spend movements" table is drawn from.

```json
{
  "currency": "USD",
  "current":  {"label": "2026-06", "services": [{"service": "Amazon EC2", "amount_usd": 4820.14}]},
  "previous": {"label": "2026-05", "services": [{"service": "Amazon EC2", "amount_usd": 4390.02}]}
}
```

A service that appears only in `current` is reported with a change in dollars
and `new` instead of a percentage — no division by zero reaches the page.

## `aws-orphan-finder` → cost findings

```json
{"account": "123456789012",
 "orphans": [{"type": "ec2:volume", "id": "vol-0a1b", "region": "eu-west-1",
              "monthly_cost_usd": 128.40, "age_days": 214, "reason": "unattached"}]}
```

Severity is graded purely on the cheque: `>= $100/month` high, `>= $25` medium,
otherwise low.

## `aws-sg-audit` → security findings

```json
{"account": "123456789012",
 "security_groups": [{"group_id": "sg-0aa1", "group_name": "bastion", "region": "eu-west-1",
                      "vpc_id": "vpc-01",
                      "open_ingress": [{"protocol": "tcp", "from_port": 22, "to_port": 22,
                                        "cidr": "0.0.0.0/0"}]}]}
```

One finding per group, graded by the worst rule in it:

| Exposure | Severity |
| --- | --- |
| A port range wider than one port, or protocol `-1`/`all` | critical |
| A single sensitive port (22, 3389, 3306, 5432, 6379, 9200, 27017, …) | critical |
| Any other single port | high |

A group with an empty `open_ingress` produces nothing.

## `s3-public-audit` → security findings

```json
{"account": "123456789012",
 "buckets": [{"name": "acme-assets", "region": "eu-west-1", "public_acl": true,
              "public_policy": false, "block_public_access": false, "public_objects": 1284}]}
```

Actually public (ACL or policy) is **critical**. Private but with Block Public
Access disabled is **medium**. A bucket that is private and has BPA on is
silent.

## `aws-iam-least-priv` → security findings

```json
{"account": "123456789012",
 "principals": [{"arn": "arn:aws:iam::123456789012:role/Deploy", "name": "Deploy", "type": "role",
                 "admin": true, "last_used_days": 210,
                 "attached_policies": ["AdministratorAccess"], "unused_services": ["rds"]}]}
```

| Condition | Rule | Severity |
| --- | --- | --- |
| admin, unused for ≥ 90 days | `dormant-admin` | critical |
| admin, recently used | `standing-admin` | high |
| non-admin with services it never touches | `unused-permissions` | low |

## `certcheck` → security findings

```json
{"certificates": [{"subject": "api.example.com", "issuer": "R3",
                   "not_after": "2026-08-01T00:00:00Z", "days_remaining": 6,
                   "origin": "acm", "region": "eu-west-1", "identifier": "arn:aws:acm:..."}]}
```

Only certificates with 45 days or fewer remaining reach the report. Expired or
≤ 7 days is critical, ≤ 14 high, otherwise medium. `origin` maps to a provider:
`acm` → aws, `keyvault` → azure, anything else → net.

## `uptime-ping` → reliability findings

```json
{"endpoints": [{"url": "https://api.example.com/health", "checks": 8640, "failures": 22,
                "uptime_pct": 99.745, "downtime_minutes": 110.0}]}
```

Endpoints at or above 99.9 % are silent. Below that: `< 99.0` critical,
`< 99.5` high, otherwise medium.

## `slo-calc` → reliability table + findings

```json
{"slos": [{"endpoint": "https://api.example.com/health", "objective_pct": 99.9,
           "attainment_pct": 99.745, "error_budget_remaining_pct": -155.0,
           "downtime_minutes": 110.0, "checks": 8640}]}
```

Every row appears in the service level attainment table, met or not. A missed
objective also raises a finding — high if the error budget is exhausted,
medium otherwise.

## `k8s-crashloop` → reliability findings

```json
{"cluster": "acme-prod", "window_hours": 720,
 "pods": [{"namespace": "payments", "pod": "api-7d9", "controller": "Deployment/api",
           "restarts": 214, "reason": "CrashLoopBackOff", "last_exit_code": 137}]}
```

≥ 50 restarts high, ≥ 10 medium, otherwise low. Exit code 137 adds the
OOM-kill explanation to the recommendation.

## `k8s-rightsize` → cost findings

```json
{"cluster": "acme-prod",
 "recommendations": [{"namespace": "payments", "workload": "api", "kind": "Deployment",
                      "cpu_request_m": 2000, "cpu_p95_m": 180,
                      "memory_request_mi": 4096, "memory_p95_mi": 512,
                      "monthly_saving_usd": 186.40}]}
```

Graded on the saving, like `aws-orphan-finder`. Lands in the **cost** section:
the deliverable is a dollar figure, not a reliability risk.

---

## Adding an adapter

1. Implement `Name() string` and `Parse([]byte, *model.Report) error` in
   `internal/adapter`.
2. `register()` it in `init()`.
3. Drop a fixture in `internal/adapter/testdata/<name>.json`.

The table-driven tests in `adapter_test.go` automatically cover every
registered adapter for empty documents and malformed input; add a
format-specific test for the grading rules.

## Finding identity

Findings are matched across months by a fingerprint:

```
<source>:<rule>:<provider>/<region>/<type>/<id>
```

Nothing that legitimately changes — a dollar amount, a timestamp, a restart
count — belongs in it. Change the fingerprint and every finding in next
month's report reads as new.
