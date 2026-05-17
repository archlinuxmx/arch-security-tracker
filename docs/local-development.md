# Local setup

Run commands from the checkout. Arch packages
provide Python 3.14 and matching pyalpm/libalpm. Source, database and package
cache stay in the checkout.

## Podman

Install Podman with `sudo pacman -Syu podman`, then build:

```sh
git submodule update --init --recursive
podman build --pull=always -f dev/Containerfile -t localhost/arch-security-tracker-dev:latest .
```

After the build succeeds, initialize a fresh tracker:

```sh
./dev/tracker python dev/configure.py
./dev/tracker setup bootstrap
./dev/tracker setup user --username denisse --email denisse@archlinux.org --role administrator
./dev/tracker update env
./dev/tracker
```

Use a password of at least 16 characters and enable the account when prompted.
`update env` downloads Arch repository databases; package matching/version
assessment need this data. Open <http://127.0.0.1:5000>, log in and create tokens
at `/tokens`. Ctrl-C stops the server; `./dev/tracker` restarts it. Only server
commands reserve port 5000; maintenance commands can run alongside the server.

The wrapper requires the local image and uses `--pull=never`. Dependencies,
including compiled pyalpm, come from pacman; no pip build is needed. Rebuild after
dependency changes. Rolling repositories may change package revisions;
`pacman -Q` lists installed versions.

```sh
curl --fail 'http://127.0.0.1:5000/api/v1/cves?limit=1'
curl --fail 'http://127.0.0.1:5000/api/v1/packages?name=openssl'
```

## Upgrade an existing database

Stop the server and keep the existing database and configuration. Run:

```sh
./dev/tracker db upgrade
./dev/tracker db check
./dev/tracker
```

This upgrades databases from `a18d5c9` while preserving their data. For native
installs, use `./trackerctl db upgrade` and `./trackerctl db check`.
Do not run `initdb`, `--purge`, or `make db-upgrade` on a production database.

## Reset development data

Disposable databases from superseded development patches may be recreated.
Stop the server, then run:

```sh
./dev/tracker db initdb --purge
./dev/tracker setup user --username denisse --email denisse@archlinux.org --role administrator
./dev/tracker update env
./dev/tracker
```

`--purge` deletes all tracker data; configuration and package cache remain.

## Native Arch Linux

Use the same packages as the image, with a full update to keep ABIs compatible:

```sh
sudo pacman -Syu --needed $(cat dev/arch-packages)
git submodule update --init --recursive
python dev/configure.py
./trackerctl setup bootstrap
./trackerctl setup user --username denisse --email denisse@archlinux.org --role administrator
./trackerctl update env
./trackerctl run --host 127.0.0.1 --port 5000
```

Arch manages these Python modules; do not install them with system pip.
An optional venv must retain them: `python -m venv --system-site-packages .virtualenv`.
For tests, run `TRACKER_CONFIG_LOCAL=false PYTHONPATH=. python -m pytest -q test`,
or `TRACKER_CONFIG_LOCAL=false ./dev/tracker python -m pytest -q test` in the image.
The development server is local-only; remote ingestion requires HTTPS.
