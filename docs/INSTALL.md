# Installing Vigil

## Requirements

| | Minimum | Comfortable |
|---|---|---|
| CPU | 1 vCPU | 2–4 vCPU |
| Memory | 1 GB | 2–4 GB |
| Disk | 10 GB | 20 GB + ~1 GB per million log lines per day of retention (see below) |
| Software | Docker Engine 20.10+ with the Compose v2 plugin ([how to install](#install-docker)) | |
| Network | FortiGate → Vigil on UDP or TCP 514; your browser → Vigil on TCP 8080 | |

Vigil runs on any 64-bit Linux host (x86-64 or ARM64), in a VM, or on Docker Desktop / WSL 2 for evaluation.

**Disk planning.** Vigil keeps the raw syslog files (rotated and compressed) and a database. As a rule of thumb, a firewall
producing 1 million log lines per day needs about 1 GB per day of detailed retention. Internet scanner noise is stored only
as counts, which keeps busy perimeter firewalls affordable.

## Install Docker

Vigil needs **Docker Engine and the Compose v2 plugin** (the `docker compose` command, with a space). Check first:

```bash
docker compose version
```

If that prints `Docker Compose version v2…` or newer, skip to [Install](#install). Otherwise pick **one** of the options
below - do not mix packages from different sources.

### Option A - Docker's official packages (recommended, all major distributions)

```bash
curl -fsSL https://get.docker.com | sudo sh
```

This adds Docker's repository and installs `docker-ce` together with `docker-compose-plugin`. It works on Ubuntu, Debian,
RHEL, Rocky, Alma, Fedora and Raspberry Pi OS. If you prefer to add the repository by hand, follow
[docs.docker.com/engine/install](https://docs.docker.com/engine/install/).

### Option B - Ubuntu's own packages (Ubuntu 22.04 / 24.04)

```bash
sudo apt update
sudo apt install -y docker.io docker-compose-v2
```

On Ubuntu's packages the Compose plugin is called **`docker-compose-v2`**. The name `docker-compose-plugin` only exists in
Docker's repository (Option A), so `apt install docker-compose-plugin` fails with *"has no installation candidate"* on a
stock Ubuntu. If you already installed `docker.io`, just add `docker-compose-v2`.

### After installing

```bash
sudo systemctl enable --now docker       # start Docker now and at every boot
sudo usermod -aG docker "$USER"          # run docker without sudo...
newgrp docker                            # ...in this shell (or log out and back in)
docker compose version                   # must print a version
docker run --rm hello-world              # optional end-to-end test
```

Membership of the `docker` group is equivalent to root on that host. If you would rather not grant it, skip the
`usermod` line and prefix the Vigil commands with `sudo` (`sudo docker compose up -d`).

## Install

```bash
git clone https://github.com/vigiltech01/vigil.git
cd vigil
cp .env.example .env        # optional: ports, retention, allowed senders
docker compose up -d
```

`docker compose up -d` pulls the published image (`ghcr.io/vigiltech01/vigil`). If the image is unavailable - for example on
an offline network with a local mirror - build it yourself with `docker compose build`.

Open `http://<host>:8080`. The first visitor creates the administrator account, so do this right after installing - or set
`VIGIL_ADMIN_USER` and `VIGIL_ADMIN_PASSWORD` in `.env` before the first start.

### Host firewall

Allow syslog from the FortiGate and the web UI from your admin network, for example with `ufw`:

```bash
sudo ufw allow from 192.0.2.1 to any port 514 proto udp      # the FortiGate
sudo ufw allow from 192.0.2.0/24 to any port 8080 proto tcp  # admin workstations
```

Note that Docker's published ports bypass `ufw` on many distributions. Restrict senders inside Vigil as well with
`VIGIL_SYSLOG_ALLOW=192.0.2.1` in `.env`.

### Port 514 already in use

If the host runs its own syslog daemon on 514, either stop it or pick another port:

```bash
echo "VIGIL_SYSLOG_PORT=5514" >> .env && docker compose up -d
```

and use `set port 5514` on the FortiGate.

## HTTPS

Run Vigil behind a reverse proxy. With [Caddy](https://caddyserver.com) (automatic certificates):

```
vigil.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

With nginx:

```nginx
server {
    listen 443 ssl http2;
    server_name vigil.example.com;
    ssl_certificate     /etc/ssl/vigil.crt;
    ssl_certificate_key /etc/ssl/vigil.key;
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

When the proxy runs on the same host, publish the web port only locally: `VIGIL_HTTP_PORT=127.0.0.1:8080`.
Session cookies are marked `Secure` automatically when the proxy sends `X-Forwarded-Proto: https`.

## Upgrade

```bash
cd vigil
git pull
docker compose pull && docker compose up -d
```

The database schema is upgraded automatically on start. Data in the `vigil-data` volume is kept.

## Backup and restore

Everything lives in the `vigil-data` volume (`vigil.db`, raw logs, uploaded configuration, settings and the admin account).

```bash
# backup (brief stop keeps the database consistent)
docker compose stop
docker run --rm -v vigil_vigil-data:/data -v "$PWD":/backup alpine tar czf /backup/vigil-backup.tgz -C /data .
docker compose start

# restore into a fresh install
docker compose down
docker run --rm -v vigil_vigil-data:/data -v "$PWD":/backup alpine sh -c "rm -rf /data/* && tar xzf /backup/vigil-backup.tgz -C /data"
docker compose up -d
```

The volume name is `<folder>_vigil-data`; check with `docker volume ls`.

## Useful commands

| Task | Command |
|---|---|
| Status | `docker compose ps` (look for `healthy`) |
| Logs | `docker compose logs -f` |
| Reset the admin password | `docker exec -it vigil python -m vigil reset-password admin` |
| Import a configuration from the host | `docker cp backup.conf vigil:/tmp/ && docker exec vigil python -m vigil import-config /tmp/backup.conf --backup-time 2026-01-15T09:30` |
| Version | `docker exec vigil python -m vigil --version` |

## Uninstall

```bash
docker compose down        # stop and remove the container, keep data
docker compose down -v     # also delete all data
```

## Running without Docker (advanced)

```bash
python3.12 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
# fetch the front-end libraries listed in the Dockerfile into web/static/vendor/
VIGIL_DATA=./data VIGIL_SYSLOG_PORT=5514 python -m vigil
```
