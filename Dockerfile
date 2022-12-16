FROM debian:bullseye

RUN apt-get update \
    && apt-get install -y  curl wget net-tools gcc make libnet-dev libglib2.0-dev tcpdump pktstat iproute2 \
    iputils-arping iputils-clockdiff iputils-ping iputils-tracepath ncat iperf3

RUN mkdir -p /tmp && cd /tmp && wget https://github.com/andrekantek/knkperf/archive/refs/heads/master.tar.gz && tar zxf master.tar.gz
RUN cd /tmp/knkperf-master/Debug && make

CMD ["/bin/bash"]
