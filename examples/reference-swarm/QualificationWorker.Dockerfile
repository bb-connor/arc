ARG BASE
FROM ${BASE}
COPY sdks/python/chio-process/src/chio_process /opt/chio/sdk/chio_process
COPY examples/reference-swarm/process-worker.py /opt/chio/process-worker.py
COPY examples/reference-swarm/process-observe-worker.py /opt/chio/process-observe-worker.py
ENV PYTHONPATH=/opt/chio/sdk PYTHONDONTWRITEBYTECODE=1
WORKDIR /work
