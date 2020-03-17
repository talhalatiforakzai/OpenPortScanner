FROM python:3.6
EXPOSE 5000
RUN apt-get update -y && \
      apt-get install -y python3-pip python3-dev build-essential
#ADD . /OPS adds eerything in OPS
WORKDIR /OPS
# Each layer is cached, and when a file that previously got copied into the image changes,
# it invalidates its cache and that of all the following layers. Therefore, we can copy a
# file that barely ever changes first
COPY requirements.txt requirements.txt

RUN pip install --upgrade pip
RUN pip install -r requirements.txt

COPY app app
COPY migrations migrations
COPY ops.py config.py boot.sh ./

ENV FLASK_APP ops.py
ENV FLASK_ENV=development
ENV FLASK_DEBUG=1
ENV FLASK_RUN_PORT=5000
RUN chmod a+x boot.sh
ENTRYPOINT ["./boot.sh"]
#CMD ["python","ops.py"]
#CMD ["flask","db","int"]
#CMD ["flask","db","migrate","-m","'done'"]
#CMD ["flask","db","upgrade"]