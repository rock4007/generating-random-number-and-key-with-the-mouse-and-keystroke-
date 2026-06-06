FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir cryptography fastapi uvicorn

COPY sdk/ ./sdk/

EXPOSE 8001

CMD ["uvicorn", "sdk.server:app", "--host", "0.0.0.0", "--port", "8001"]
