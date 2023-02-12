FROM python:3.10-slim-buster

RUN apt-get update && apt-get -y install cron vim

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip3 install -r /app/requirements.txt

COPY crontab /tmp/crontab
RUN crontab /tmp/crontab

COPY dns_record_updater.py /app/dns_record_updater.py

CMD ["cron", "-f"]
