# ADR 0003: one Control Plane core crate, services as modules

Status: accepted.

The specification lists eight services as directories. At this stage they
share one consistent view of tenants, installations, licenses and packages, and
the interesting security properties (tenant isolation, revocation ordering,
fail-closed policy) live in the interactions. Splitting into crates now would
only add plumbing. `control-plane/core` therefore holds the logic; the HTTP
gateway and the storage layer will sit around it. Split when a service needs
independent deployment.

Known debt: state is in memory. When PostgreSQL support lands, the storage
operations become an async `Store` trait; `sqlx`/`tokio-postgres` are async, so
the current synchronous in-memory methods will be refactored, and
`control-plane/migrations/0001_init.sql` is the target schema.
