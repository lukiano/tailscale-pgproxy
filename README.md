# PostgreSQL connection proxy through Tailscape

## Version 1

- `pgproxy` logs queries. 
- Tailscale users with email ending in `gmail.com` have readonly access to the database.

### Assumptions
- The Postgres server should have SSL enabled and `pg.crt` should be its certificate.
- The Postgres server is locally running on `localhost`. Otherwise, replace with the proper host.

### How to run

```bash
go run pgproxy.go --hostname pgproxy --upstream-addr localhost:5432 --upstream-ca-file pg.crt --state-dir .
```

## Version 2 with secrets managements

### Assumptions
- Tailscape's [Secret Management Tool](https://tailscale.com/docs/features/access-control/grants/grants-app-capabilities#setec) is up and running.
- Custom capabilities added by an Tailscale admin oo the *Access Controls* tab, `JSON Editor`

### How to run

```bash
go install github.com/tailscale/setec/cmd/setec@latest
```
to download the `setec` server

```bash
TS_AUTHKEY=... ~/go/bin/setec server --state-dir ~/setec --hostname secrets --dev
```
to run the server with a hostname `secrets` in _dev_ mode to avoid needing AWS KMS setup.

```
~/go/bin/setec put prod/db/ro-user -s https://secrets.<tailscape domain>
~/go/bin/setec put prod/db/ro-pass -s https://secrets.<tailscape domain>
```
to store the Postgres credentials in the secrets manager.

#### Access controls example

```json
{
    "groups": {
        "group:database-users": [ database users ]
    },
    "tagOwners": {
        "tag:database-service": ["autogroup:admin"]
    },
    "grants": [
        {
            "src": ["group:database-users"],
            "dst": ["tag:database-service"],
            "app": {
                "tailscale.com/cap/secrets": [
                    {
                        "action": ["get"],
                        "secret": ["prod/db/ro-user", "prod/db/ro-pass"]
                    }
                ]
            }
        },
        {
            "src": ["autogroup:main"],
            "dst": ["*"],
            "app:" {
                "tailscale.com/cap/secrets": [
                    {
                        "action": ["get", "put", "info", "activate", "delete"],
                        "secret": ["*"]
                    }
                ]
            }
        }
    ]
}
```
The admin should tag the `secrets` service with `tag:database-service`.

