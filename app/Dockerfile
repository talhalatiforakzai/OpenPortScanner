FROM python:3.7

EXPOSE 5000

RUN apt-get update -y && \
 		apt-get install -y python3-pip python3-dev nmap build-essential

WORKDIR /app

COPY requirements.txt /app
COPY open_ports.sh /app

RUN pip install --upgrade pip
RUN pip install -r requirements.txt

COPY app.py /app
CMD python app.py