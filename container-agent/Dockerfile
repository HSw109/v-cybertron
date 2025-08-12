FROM ubuntu:22.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl git jq python3 python3-pip tar gnupg \
 && rm -rf /var/lib/apt/lists/*

# Trivy
RUN curl -fsSL "https://get.trivy.dev/trivy?type=tar.gz&version=0.65.0&os=linux&arch=amd64" -o /tmp/trivy.tar.gz \
 && tar -xzf /tmp/trivy.tar.gz -C /usr/local/bin trivy \
 && rm -f /tmp/trivy.tar.gz \
 && trivy --version

# Grype
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin v0.79.2 \
 && grype version

# Dockle
RUN curl -sSfL https://github.com/goodwithtech/dockle/releases/download/v0.4.15/dockle_0.4.15_Linux-386.tar.gz -L -o /tmp/dockle.tgz \
 && tar -xzf /tmp/dockle.tgz -C /usr/local/bin dockle \
 && rm -f /tmp/dockle.tgz \
 && dockle --version

COPY ./app /app
WORKDIR /app
COPY requirements.txt /app/requirements.txt 
RUN pip install -r /app/requirements.txt

EXPOSE 5001

CMD ["python3", "server.py"]


