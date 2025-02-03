ARG ARCH=
FROM ${ARCH}python:3.12.3-alpine3.19 AS base

LABEL org.opencontainers.image.source https://github.com/arthursimas1/eztunnel

FROM base AS runtime

COPY sock_tcp_client.py /
COPY sock_tcp_server.py /
COPY sock_udp_client.py /
COPY sock_udp_server.py /

STOPSIGNAL SIGINT
