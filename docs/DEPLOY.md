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

1. Push the repo to GitHub (`push.bat`).
2. Sign in at **<https://render.com>** with GitHub. No card.
3. **New → Web Service** → pick the `SG-Hackathon` repo.
4. Render reads `render.yaml` and fills everything in. Confirm:
   - Runtime **Docker**, Plan **Free**, Health check **`/health`**
5. **Create Web Service.** First build takes 4–6 minutes (it installs scikit-learn).

Your URL: `https://sbomguard.onrender.com` (Render will tell you the exact one).

`autoDeploy` is on, so every `git push` redeploys.

---

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
