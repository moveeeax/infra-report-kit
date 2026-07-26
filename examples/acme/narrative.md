## What changed this month

Spend rose by **$700.71**, almost entirely in EC2 and data transfer. The EC2
increase is the new `settlement` node group, which is expected. Data transfer
more than doubled and is not expected: the search indexer began pulling its
corpus across availability zones on 12 June.

## What we recommend, in order

- **Close the two internet-facing databases first.** `sg-0cc99dd00ee11ff22` in
  eu-central-1 exposes every TCP port to the world, including PostgreSQL. This
  is a one-line change and it is the finding we would not leave open overnight.
- **Delete the contractor account.** `contractor-2023` holds
  `AdministratorAccess` and has not been used in over a year.
- **Renew `legacy.example.com`.** The certificate expired eight days ago; the
  endpoint is currently serving a browser warning.
- **Right-size `payments/settlement`.** It requests eleven times the CPU it
  uses at p95. This alone is $186/month.

## What it costs to fix

Roughly a day of our time. The security items are configuration changes with no
downtime. The rightsizing needs one deploy per workload and a week of watching
p95 latency afterwards. Against $366/month of identified waste, the work pays
for itself inside the quarter.
