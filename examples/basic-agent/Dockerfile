FROM python:3.12-slim

WORKDIR /app

RUN pip install groq --no-cache-dir

COPY agent.py .

CMD ["python", "agent.py"]
