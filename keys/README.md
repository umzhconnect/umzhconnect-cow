# keys — this party's L2 signing key

The key-custodian signs `private_key_jwt` client assertions with this party's
**L2 private key** and serves the matching **public JWK Set** (fetched by the
auth server via the client's `jwks.url`, and exposed at the gateway's
`/jwks.json`).

The private key is a **secret and is never committed** — `l2.key` and
`l2.jwks.json` are gitignored. Generate a local demo pair before the first
`docker compose up`:

```bash
keys/gen-keys.sh l2      # basename must equal L2_KID in .env (default: l2)
```

This writes `keys/l2.key` (private) + `keys/l2.jwks.json` (public), with the JWK
`kid` set to `l2` (so it matches `L2_KID`). `docker-compose.yml` mounts
`./keys/l2.key` and `./keys/l2.jwks.json` into the custodian.

## Production

Do **not** ship a repo-generated key to production. Generate the keypair once
per party per environment during provisioning, store the private key in a secret
manager / KMS (ideally non-exportable), and mount it from there — the repo holds
no key material. Rotate on a schedule using distinct `kid`s (publish the new
public key in the JWKS, sign with the new `kid`, retire the old one after
propagation) so rotation causes no downtime.
