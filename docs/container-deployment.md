# Container deployment

The root `Containerfile` packages the tracker and Gunicorn for Linux AMD64
(x86_64), using the official Arch Linux base image and packages.

The image runs as UID/GID 10001, listens on port 8080, and stores the database
and package cache in `/var/lib/tracker`. Keep that directory on persistent
storage. SQLite needs a local filesystem or an attached block volume, not NFS.
Use one application replica; deploying on Kubernetes does not make SQLite a
distributed database.

For an OCI image built with Podman:

```sh
git submodule update --init --recursive
podman build --platform linux/amd64 -f Containerfile \
  -t localhost/arch-security-tracker:latest .
```

The package transaction uses rolling Arch repositories. Publish and deploy image
digests for rollbacks. Compose explicitly selects `linux/amd64`.

## Compose

Initialize the submodules and create a private secret directory. Only the secret
file is mounted into the containers; its permissions must allow UID 10001 to read
it. Keep the same key across restarts and upgrades.

```sh
git submodule update --init --recursive
install -d -m 700 secrets
test -e secrets/tracker-secret || openssl rand -hex 32 > secrets/tracker-secret
chmod 444 secrets/tracker-secret
docker compose build --pull
docker compose run --rm web init
docker compose run --rm web trackerctl setup user --role administrator
docker compose run --rm web refresh
docker compose up -d
```

Open <http://127.0.0.1:8080>. `init` only accepts a fresh database. The maintenance
container refreshes package data immediately, then every six hours. Failed
refreshes retain the previous cache. Concurrent refreshes use a file lock.

For `security.archlinux.mx`, persist these settings in your deployment
environment before starting Compose:

```sh
export TRACKER_PUBLIC_URL=https://security.archlinux.mx
export TRACKER_PROXY_HOPS=1
docker compose up -d
```

Route your trusted HTTPS proxy or Cloudflare Tunnel to `127.0.0.1:8080`. The port
is bound to loopback. Trust one forwarded-header hop only when that proxy is the
sole route to the service; set the count for your actual proxy chain. An HTTPS
public URL enables secure session cookies.

For an upgrade, stop both containers and back up the data volume and secret.
Then build the new image, migrate, and restart:

```sh
docker compose stop
docker compose build --pull
docker compose run --rm web migrate
docker compose up -d
```

Startup never initializes or migrates the database automatically. Existing
databases, including the production baseline, use `migrate`, not `init`.
`docker compose down` retains the named volume; `down -v` deletes it.

## Kubernetes

Build and push the AMD64 image to your registry:

```sh
docker buildx build --platform linux/amd64 \
  -f Containerfile -t REGISTRY/arch-security-tracker:TAG --push .
```

In `deploy/kubernetes/deployment.yaml` and `database/job.yaml`, replace
`arch-security-tracker:local` with that tag or digest. Set your storage class in
`pvc.yaml` and domain in `configmap.yaml`. The default storage request is 5 GiB;
adjust it for your data. Use a namespace dedicated to this deployment.

Create the secret and storage before starting the application:

```sh
kubectl create secret generic arch-security-tracker \
  --from-file=secret_key=secrets/tracker-secret
kubectl apply -f deploy/kubernetes/configmap.yaml -f deploy/kubernetes/pvc.yaml
kubectl apply -k deploy/kubernetes/database
kubectl wait --for=condition=complete job/arch-security-tracker-database --timeout=300s
kubectl logs job/arch-security-tracker-database
kubectl delete -k deploy/kubernetes/database --cascade=foreground --wait=true
kubectl apply -k deploy/kubernetes
kubectl rollout status deployment/arch-security-tracker
kubectl exec -it deployment/arch-security-tracker -c web -- \
  python /opt/tracker/deploy/entrypoint.py trackerctl setup user --role administrator
```

The database Job is deliberately excluded from the Kustomization. Its default
`args: [init]` is for a fresh volume. Continue to the application deployment only
after the Job succeeds. For a pre-existing database, use `args: [migrate]`.

The application and maintenance containers share one volume in the same Pod.
Both the application and database Job select Linux AMD64 nodes.
`Recreate` prevents rolling updates from running two application Pods. Tune the
resource requests and limits after measuring your package cache and workload.
The liveness check is `/healthz`; `/readyz` also checks the schema revision.

For cluster upgrades, stop the workload before running the database Job:

```sh
kubectl scale deployment/arch-security-tracker --replicas=0
kubectl wait --for=delete pod -l app=arch-security-tracker --timeout=180s
```

Back up the volume, update both image references, and set the Job's
`args: [migrate]`. Apply, wait for, and delete the Job as above, then apply the
Kustomization to start the new version. Keep the workload stopped if migration
fails. Do not increase the replica count or run a second deployment on this data.

For HTTPS ingress, set your controller's class in `ingress.yaml`, create the
`arch-security-tracker-tls` TLS Secret, and apply that file separately. No
certificate issuer or ingress controller is assumed. Set `TRACKER_PROXY_HOPS`
in the ConfigMap only when network policy restricts access to your trusted proxy.
Cloudflare Tunnel can instead target the ClusterIP service on port 8080.

## Runtime settings

| Variable | Default or requirement |
| --- | --- |
| `TRACKER_PUBLIC_URL` | Required; HTTPS URL, or HTTP loopback for local use |
| `TRACKER_SECRET_KEY_FILE` | File containing a private key of at least 32 characters |
| `TRACKER_SECRET_KEY` | Alternative to the secret file |
| `TRACKER_DATA_DIR` | `/var/lib/tracker` |
| `TRACKER_CONFIG_FILE` | Optional mounted INI file for SSO and other application settings |
| `TRACKER_PROXY_HOPS` | `0`; trust forwarded headers only from an isolated proxy path |
| `TRACKER_WORKERS` | `1`; keep low for SQLite and small machines |
| `TRACKER_REFRESH_INTERVAL` | `21600` seconds |

Mount advanced configuration read-only and keep credentials out of images.
The root filesystem can be read-only with writable mounts for the data directory
and `/tmp`, as shown in both deployment examples.
