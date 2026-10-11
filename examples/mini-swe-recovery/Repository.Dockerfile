ARG BASE=python:3.11-slim
FROM ${BASE}
USER 0:0
RUN apt-get update && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*
USER 65534:65534
