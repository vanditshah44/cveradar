# Backend deployment (Railway)

Three Railway services — **backend**, **worker**, **beat** — all build from this
same directory and therefore share this `railway.json`.

## Why `startCommand` is not in `railway.json`

Each service needs a *different* start command. A `startCommand` in this shared
file is applied to **all three**, which on 2026-07-22 silently replaced the
celery commands on `worker` and `beat` with the API's uvicorn command and took
the whole pipeline down — matching, syncs and scheduling all stopped while the
API itself kept reporting healthy.

The commands live in each service's Railway settings instead:

| Service | Start command |
|---|---|
| backend | `sh -c 'uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000} --workers 2'` |
| worker  | `celery -A app.tasks.celery_app worker --loglevel=info --concurrency=2` |
| beat    | `celery -A app.tasks.celery_app beat --loglevel=info` |

`preDeployCommand: alembic upgrade head` is safe to keep here only because it is
idempotent, but it is set on **backend** at deploy time so migrations run once
rather than racing across three services.

## Deploying with the CLI

`railway up` from inside the git repo silently drops untracked files, so deploy
from a staged copy outside the repo, with that service's own `railway.json`:

```sh
STAGE=$(mktemp -d)
rsync -a --exclude '.venv/' --exclude '__pycache__/' --exclude '*.pyc' \
      --exclude '.pytest_cache/' --exclude 'tmp/' --exclude '.env' backend/ "$STAGE"/
# edit "$STAGE/railway.json" -> deploy.startCommand for the target service
cd "$STAGE"
railway link --project <project-id> --environment production --service <service>
railway up --service <service> --ci
```

Deploy services **sequentially**, not in parallel.

## After every deploy, check the worker

The API returns healthy even when celery is dead, so this is the check that
actually matters:

```sh
curl -s https://backend-production-6537.up.railway.app/health/ready
```

`celery_worker` must be `ok` with a worker listed, and `celery_beat` must show a
recent heartbeat.
