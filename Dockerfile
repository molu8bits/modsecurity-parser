FROM ubuntu:22.04

LABEL maintainer "molu8bits@gmail.com"
LABEL description "modsecurity parse and charts via Docker"
LABEL version "2023.05 v0.5"

ENV DEBIAN_FRONTEND=noninteractive

RUN mkdir -p /opt/mparser/
COPY requirements.txt /opt/mparser/

RUN apt-get update && apt-get install -y git && \
  apt-get install -y wget && \
  apt-get install -y python3 python3-pip
  #python3-matplotlib python3-numpy python3-pandas python3-openpyxl

RUN pip3 install -r /opt/mparser/requirements.txt

COPY modsecurity_parser.py /opt/mparser/
COPY run.sh /opt/mparser/

RUN chmod +x /opt/mparser/run.sh

#ENTRYPOINT [ "skippedbynow" ]
CMD [ "/opt/mparser/run.sh" ]
