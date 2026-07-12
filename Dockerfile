# SBOMGuard — container image.
#
# Targeted at Hugging Face Spaces (which requires port 7860 and a non-root user), but
# there is nothing HF-specific in here: it will run anywhere that takes a Dockerfile.
#
#   docker build -t sbomguard .
#   docker run -p 7860:7860 sbomguard
#
# No secrets, no database, no volumes. The dataset ships in the image and the front end is
# pre-built, so the container is self-contained: it does not phone home to a CDN, and it
# does not need an API key to start. A demo that depends on someone else's uptime is not a
# demo.

FROM python:3.11-slim

# HF Spaces runs containers as uid 1000. Match it, so the app can write its own
# artifacts/ and reports/ directories without a permissions surprise on first boot.
RUN useradd -m -u 1000 app

WORKDIR /app

# Dependencies first, so a code change doesn't re-download scikit-learn every build.
COPY --chown=app:app requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=app:app . .

USER app

ENV PYTHONPATH=/app/src \
    PYTHONUNBUFFERED=1 \
    PORT=7860

EXPOSE 7860

# Single worker on purpose. The analysis is held in memory and built once at startup;
# a second worker would rebuild the whole estate for no benefit and double the RAM.
CMD ["uvicorn", "sbomguard.api:app", "--host", "0.0.0.0", "--port", "7860", "--workers", "1"]
