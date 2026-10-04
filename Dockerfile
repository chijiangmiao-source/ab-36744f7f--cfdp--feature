FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    CFDP_AUDIT_HOST=0.0.0.0 \
    CFDP_AUDIT_PORT=8080

WORKDIR /srv

COPY app ./app
COPY tests ./tests
COPY smoke.py verify.sh ./
RUN chmod +x verify.sh && python -m compileall -q app

EXPOSE 8080

CMD ["python", "-m", "app.server"]
