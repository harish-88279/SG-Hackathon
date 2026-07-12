# Deploying SBOMGuard

**Free, no credit card, ~10 minutes.**

---

## Why Render

We checked the alternatives before writing any of this, because picking the wrong host
loses you the room before the app even loads.

| Host | Verdict |
|---|---|
| **Render** | ✅ **Use this.** Free tier, no card, deploys the Dockerfile as-is. |
| Hugging Face Spaces | ❌ Docker Spaces are now a **paid** SDK. Only Gradio and Static are free, and neither will serve a FastAPI backend. |
| Vercel | ❌ Serverless. scikit-learn + numpy exceed the 250MB bundle limit, there is no persistent process to hold the dependency graph in memory (it would rebuild all 500 components on *every request*), and the execution timeout kills the live evaluation. Wrong shape for this app. |
| Koyeb | ⚠️ Free, but 0.1 vCPU. It will run and it will crawl. |
| Fly.io / Cloud Run | ❌ Both now require a card. |

**It fits.** Measured resident set is **191MB**, including running both evaluation harnesses
live — against Render's 512MB ceiling. scikit-learn is most of that.

---

## Deploy

Two paths. **Pick one.** The second is fewer moving parts and builds faster, so it is the
one to use unless you specifically want the container.

### A. Native Python (recommended — no image build)

1. Push to GitHub (`push.bat`).
2. Sign in at **<https://render.com>** with GitHub. No card.
3. **New → Web Service** → pick the `SG-Hackathon` repo.
4. Render will guess **Language: Python 3**. That is correct. Then set:

   | Field | Value |
   |---|---|
   | **Build Command** | `pip install -r requirements.txt` |
   | **Start Command** | `PYTHONPATH=src python -m uvicorn sbomguard.api:app --host 0.0.0.0 --port $PORT` |
   | **Instance Type** | Free |

   Render pre-fills the Start Command with a greyed-out `gunicorn your_application.wsgi`.
   That is a **placeholder, not a value** — and it would not work anyway: gunicorn is a
   *WSGI* server and FastAPI is *ASGI*. Replace it with the line above.

   Two details in that command are load-bearing. `PYTHONPATH=src` because the package lives
   at `src/sbomguard`, not at the repo root. And `$PORT` because Render injects the port —
   hardcode one and the health check never passes.

5. **Create Web Service.** First deploy takes 3–5 minutes (installing scikit-learn).

### B. Docker

Same steps, but on the create page change the **Language** dropdown from *Python 3* to
**Docker**. The Build and Start Command fields disappear; Render uses the `Dockerfile`.

> **`render.yaml` is only read by Blueprints, not by Web Services.** If you want Render to
> configure itself from that file, you must use **New → Blueprint** instead of **New → Web
> Service**. Creating a plain Web Service ignores it entirely — which is exactly why the
> form asked you for a start command.

Your URL will be `https://sbomguard.onrender.com` (Render tells you the exact one).
Auto-deploy is on, so every `git push` ships.

## The one thing that will bite you on demo day

**The free instance sleeps after 15 minutes of inactivity, and takes ~50 seconds to wake.**

A judge who clicks your link cold stares at a blank tab for the better part of a minute and
concludes it is broken. This is the single most likely way a working project loses marks.

Do both of these:

**Warm it up before you present.** Open the link 2 minutes before the demo. That's it.

**Keep it awake during judging.** Set up a free pinger — <https://cron-job.org> (free, no
card) — to hit `https://<your-app>.onrender.com/health` every 10 minutes. `/health` is a
trivial endpoint that returns `{"status":"ok"}` without touching the analysis, so this costs
essentially nothing.

---

## Verifying the deploy

```
https://<your-app>.onrender.com/health         -> {"status":"ok","version":"1.0.0"}
https://<your-app>.onrender.com/               -> redirects into the dashboard
https://<your-app>.onrender.com/docs           -> all 29 endpoints, live
```

Then click **Scorecard → Run the official evaluation**. If it returns 3/5 with the log4j-api
proof, the deployment is genuinely working — that button runs the real harness against the
real labels, on the server, right now.

---

## Running it locally instead

Nothing about the demo requires hosting at all:

```
start.bat
```

or, with Docker:

```
docker build -t sbomguard .
docker run -p 8000:8000 sbomguard
```

The image is self-contained: the dataset ships inside it, the front end is pre-built, and no
API key is needed to start. **It cannot be taken down by someone else's outage** — which,
for a supply-chain project, is a point worth making out loud.
