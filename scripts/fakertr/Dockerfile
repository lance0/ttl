FROM ubuntu:24.04
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends python3 iproute2 >/dev/null && rm -rf /var/lib/apt/lists/*
COPY fakertr.py /fakertr.py
COPY setup.sh /setup.sh
RUN chmod +x /setup.sh
ENTRYPOINT ["/setup.sh"]
