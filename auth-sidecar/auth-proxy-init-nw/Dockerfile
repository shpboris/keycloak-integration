FROM ubuntu:18.04
RUN apt-get update && \
    apt-get install -y iptables
COPY init.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/init.sh
ENTRYPOINT ["init.sh"]


