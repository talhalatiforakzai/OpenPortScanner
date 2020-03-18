FROM python:3.6

RUN apt-get update -y && \
      apt-get install -y python3-pip python3-dev build-essential

WORKDIR /OpenPortScanner

COPY requirements.txt requirements.txt

RUN pip install --upgrade pip
RUN pip install -r requirements.txt
RUN pip install gunicorn

COPY app app
COPY migrations migrations
COPY bin bin
COPY ops.py config.py ./

ENV CELERY_BROKER_URL redis://redis:6379/0
ENV CELERY_RESULT_BACKEND redis://redis:6379/0
ENV C_FORCE_ROOT true
ENV FLASK_APP ops.py
ENV FLASK_ENV=development
ENV FLASK_DEBUG=1
ENV FLASK_RUN_PORT=5001

RUN chmod a+x /OpenPortScanner/bin/boot.sh
RUN chmod a+x /OpenPortScanner/bin/worker.sh
RUN chmod a+x /OpenPortScanner/bin/monitor.sh

