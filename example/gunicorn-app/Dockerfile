FROM arm64v8/ubuntu:20.04

RUN apt-get update && apt-get install -y python3.9 python3.9-venv

WORKDIR /opt/app
COPY server.py /opt/app
COPY requirements.txt /opt/app
RUN python3.9 -m venv .env
RUN .env/bin/python3.9 -m pip install -r requirements.txt
ENV FLASK_APP "server.py"

ENTRYPOINT ["/opt/app/.env/bin/gunicorn", "server:app"]
CMD ["-w", "4", "-b", "0.0.0.0:5000"]
