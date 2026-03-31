# How to run

The Postgres server should have SSL enabled and `pg.crt` should be its certificate.

Assumes the Postgres server is locally running on `localhost`. Otherwise, replace with the proper host.

```bash
go run pgproxy.go --hostname pgproxy --upstream-addr localhost:5432 --upstream-ca-file pg.crt --state-dir .
```
