FROM ubuntu:18.04
LABEL maintainer "molu8bits@gmail.com"
LABEL description "modsecurity parse and charts via Docker"
LABEL version "2020.09 v0.3"

ENV DEBIAN_FRONTEND=noninteractive

RUN mkdir -p /opt/mparser/
COPY requirements.txt /opt/mparser/

RUN apt-get update && apt-get install -y git && \
  apt-get install -y wget && \
  apt-get install -y python3 python3-pip
  #python3-matplotlib python3-numpy python3-pandas python3-openpyxl

RUN pip3 install -r requirements.txt

COPY modsecurity-parser.py /opt/mparser/
COPY run.sh /opt/mparser/

RUN chmod +x /opt/mparser/run.sh

#ENTRYPOINT [ "skippedbynow" ]
CMD [ "/opt/mparser/run.sh" ]
