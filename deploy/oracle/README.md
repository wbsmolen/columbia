# Oracle egress: Columbia's Reddit-facing services on an Always Free VM

Reddit rate-limits Cloudflare's egress IPs, so the `columbia-relay` and
`columbia-commons` Workers hand Reddit-bound work to an egress origin
(`EGRESS_RELAY_ORIGIN` / `EGRESS_COMMONS_ORIGIN`). Until now that was Azure. This
kit moves it to one Oracle Cloud Always Free Ampere A1 VM:

```
app ── relay.landerapp.xyz / commons.landerapp.xyz (Workers)
          │  x-azure-fdid: REQUIRE_FDID, x-azure-socketip: app IP
          ▼
   egress.landerapp.xyz:443  (Caddy, Let's Encrypt over TLS-ALPN)
     /relay /ohttp-configs /health ─► relay ──https──► gateway ─► oauth.reddit.com, matrix.redditspace.com
     everything else (/v1/*) ──────► commons ─► oauth.reddit.com, api.imgur.com
     gateway's commons requests ─► Caddy :8081 (internal, adds the FDID) ─► commons
```

The relay, gateway and commons run with the same images and settings as the Azure
container apps. The relay and commons accept only requests carrying
`x-azure-fdid` = `REQUIRE_FDID` (the same env var Azure uses; the Workers already
send it). Only `GET /health` is open. If the VM is down, the Workers fall back to
Cloudflare's own egress: more Reddit 429s, but no outage.

| File | What it does |
|---|---|
| `up.sh` | OCI CLI provisioning, idempotent: VCN, internet gateway, security list (443 open, 22 from your IP), public subnet, `VM.Standard.A1.Flex` 2 OCPU / 12 GB Ubuntu 24.04 aarch64, reserved public IP, local ssh key. Retries "Out of host capacity" across every availability domain. |
| `cloud-init.yaml` | Installs Docker + compose + git, clones this repo to `/opt/columbia`. |
| `compose.yaml`, `Caddyfile` | The stack. Secrets come from `/etc/columbia/egress.env`; compose refuses to start without them, so the gateway can't come up on a random key. |
| `secrets.sh` | `save`: reads the secret values from Azure (or the cf-migration keys dir) into `~/Documents/lander-ops/oracle-egress/secrets/egress.env`, mode 600. `push`: ships that file to the VM over ssh and starts the stack. |
| `dns.sh` | Creates or updates the DNS-only `egress.landerapp.xyz` A record. |
| `cutover.sh` | `check` (canary), `deploy` (moves the Workers, verifies, rolls back on failure), `verify`, `rollback`. |
| `up_test.sh` | Runs `up.sh` against a fake `oci`; needs no Oracle account. |

Nothing secret is in this directory. Everything the scripts write lives under
`~/Documents/lander-ops/oracle-egress/`: `secrets/egress.env`, `ssh/`, `state.env`,
`cutover-previous.env`.

## Owner steps

Run everything from `deploy/oracle/` in a checkout of this repo. You need
`oci`, `jq`, `go` and `npx`, and you need to be logged in to wrangler
(`npx wrangler@4 whoami`).

1. **Secrets: already saved (Nov 15 2026).** `secrets/egress.env` holds the
   gateway seed, the relay→gateway secret, `REQUIRE_FDID` and `IMGUR_CLIENT_ID`.
   After Azure is gone it is the only readable copy of `REQUIRE_FDID`:
   Cloudflare Worker secrets are write-only. Keep it backed up.
   To refresh it while Azure still runs: `./secrets.sh save`.

2. **Oracle account and API key.** Sign up for Oracle Cloud Free Tier and pick
   the home region with care: it can't change, and A1 capacity varies by region.
   - In the Console, open Profile → *API keys* → *Add API key* → *Paste a public key*.
     Paste `~/.oci/oci_api_key_public.pem` (fingerprint `93:1f:47:97…`).
   - Copy the configuration preview the Console shows into `~/.oci/config`, and set
     `key_file=~/.oci/oci_api_key.pem`.
   - Check it: `oci iam availability-domain list` prints your ADs.

3. **Provision:**
   ```sh
   COLUMBIA_REF=feat/oracle-egress ./up.sh   # once this PR is merged: ./up.sh
   ```
   If every AD is out of A1 capacity, it keeps retrying for up to 2 hours
   (`RETRY_SECONDS`, `MAX_ROUNDS`). Re-running is safe at any time; it also
   refreshes the ssh rule when your IP changes. It prints the VM's IP.

4. **DNS:** `./dns.sh` creates `egress.landerapp.xyz` → VM IP, DNS only.
   `DRY_RUN=1 ./dns.sh` previews the change.

5. **Ship secrets and start the stack:** `./secrets.sh`. The first run builds the
   images on the VM, which takes a few minutes. Caddy then gets its certificate;
   the HTTP challenge fails on closed port 80 and it falls back to TLS-ALPN, which
   takes about a minute. To watch:
   `ssh -i ~/Documents/lander-ops/oracle-egress/ssh/id_ed25519 ubuntu@<ip> sudo docker logs -f columbia-egress-caddy-1`

6. **Canary:** `./cutover.sh check`. Every line must say `ok`. It checks:
   - health
   - the origin lock: no FDID → 403 on `/ohttp-configs`, `/relay` and commons
   - the key config matches the one apps pin (`c6871a30…`)
   - real OHTTP round trips: Reddit answers with its own 403 page, matrix with 200,
     commons on the VM with 400
   - commons reaches Reddit without a 429

7. **Cut over:** `./cutover.sh deploy`. It runs the canary, records the current
   origins in `cutover-previous.env`, sets both origins to
   `https://egress.landerapp.xyz` in `workers/{relay,commons}/wrangler.toml`, and
   runs `npx wrangler@4 deploy` on both. It then verifies through
   `relay.landerapp.xyz` / `commons.landerapp.xyz` and confirms in the VM's
   container logs that Oracle, not the Cloudflare fallback, served the requests.
   If any of that fails, it rolls back on its own. Commit the `wrangler.toml`
   change in a PR afterwards.
   `DRY_RUN=1 ./cutover.sh deploy` rehearses it: it bundles both Workers, deploys
   nothing, and restores the files.

8. **Rollback, if needed:**
   - `./cutover.sh rollback` restores the origins recorded in step 7 (Azure, while it lasts).
   - `./cutover.sh rollback none` sets no egress origin, so the Workers use Cloudflare's IPs.

## Day-2

```sh
SSH="ssh -i ~/Documents/lander-ops/oracle-egress/ssh/id_ed25519 ubuntu@$(. ~/Documents/lander-ops/oracle-egress/state.env; echo $EGRESS_IP)"
$SSH sudo docker ps
$SSH sudo docker logs --since 1h columbia-egress-commons-1 | grep -c upstream_429   # Reddit throttling this IP?
# Deploy new code:
$SSH 'cd /opt/columbia && sudo git pull && cd deploy/oracle && sudo docker compose --env-file /etc/columbia/egress.env up -d --build'
# Rotate a secret: edit secrets/egress.env, then
./secrets.sh push
```

To change `REQUIRE_FDID`, set the new value on both Workers
(`npx wrangler@4 secret put REQUIRE_FDID` in `workers/relay` and `workers/commons`)
and in `egress.env`, then `./secrets.sh push`.

## Caveats

- **Idle reclamation.** Oracle can reclaim an Always Free VM that is idle for 7
  days. On A1 that means CPU, network and memory all stay under 20% at the 95th
  percentile, and this stack is light. Upgrading the account to Pay As You Go
  exempts Always Free resources and still bills $0 inside the free limits, but it
  needs a card on file, so it's the owner's call. If the VM is reclaimed, the
  Workers fall back to Cloudflare egress; re-run `up.sh` then `secrets.sh`. The
  reserved IP, and so the DNS record, survive.
- **Free limits used:** one A1 VM (2 OCPU / 12 GB, the 2026 Always Free cap),
  1 reserved IPv4, 1 VCN, a ~47 GB boot volume, and outbound data well under
  10 TB/month (the relay sent ~88 GB/week on Azure). `OCPUS=1 MEMORY_GB=6 ./up.sh`
  if the tenancy only has half the allowance left.
- **Non-collusion:** relay and gateway share one VM and one operator, as they did
  on Azure. See `../../SELFHOSTING.md`.
- **Privacy:** Caddy keeps no access log. The relay and commons log only
  route/status/latency, and the gateway logs only startup, as on Azure. Docker logs
  rotate (`local` driver, 5 × 20 MB per container).
