FROM ubuntu:18.04
LABEL maintainer "molu8bits@gmail.com"
LABEL description "modsecurity parse and charts via Docker"
LABER version "2019.01 v0.1"

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y git && \
  apt-get install -y wget && \
  apt-get install -y python3 python3-matplotlib python3-numpy python3-pandas python3-openpyxl
RUN mkdir -p /opt/mparser/


COPY modsecurity-parser.py /opt/mparser/
COPY run.sh /opt/mparser/


#ENTRYPOINT [ "skippedbynow" ]
CMD [ "/opt/mparser/run.sh" ]
