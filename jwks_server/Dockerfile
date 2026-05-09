FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir flask cryptography

COPY server.py .

EXPOSE 9000

CMD ["python", "server.py"]
