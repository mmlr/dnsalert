FROM python:3.13-alpine

WORKDIR /source

COPY dnsalert.py .

ENTRYPOINT ["/source/dnsalert.py"]
