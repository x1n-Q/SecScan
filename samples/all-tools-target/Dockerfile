FROM python:3.8-slim

WORKDIR /app
COPY python-app/requirements.txt /app/requirements.txt
RUN pip install -r /app/requirements.txt

CMD ["python", "-m", "http.server", "8080"]
