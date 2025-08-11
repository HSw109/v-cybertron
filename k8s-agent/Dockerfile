FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl git jq python3 python3-pip tar \
 && rm -rf /var/lib/apt/lists/*

# Install kube-linter
RUN curl -sSL https://github.com/stackrox/kube-linter/releases/latest/download/kube-linter-linux.tar.gz \
 | tar -xz -C /usr/local/bin kube-linter

# Install OPA
RUN curl -L -o /usr/local/bin/opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64 \
 && chmod +x /usr/local/bin/opa

WORKDIR /app
COPY ./app /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

EXPOSE 5002
CMD ["python3", "server.py"] 