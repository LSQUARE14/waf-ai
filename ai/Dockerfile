FROM nvidia/cuda:12.8.0-runtime-ubuntu22.04

RUN apt update && apt install -y sqlite3 python3 python3-pip

WORKDIR /ml_detector

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["python3", "run.py"]