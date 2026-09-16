FROM python:3.14.7-slim@sha256:cad9a2c871761c413caa6fdd6441c783451e740a48aaeba60ae62a8b53525ef6
RUN apt-get update && apt-get install -y --no-install-recommends socat squid git procps util-linux curl ca-certificates && rm -rf /var/lib/apt/lists/*
COPY examples/codex_contained/install_client.py /opt/proof/install_client.py
RUN python /opt/proof/install_client.py
RUN pip install --no-cache-dir --report /opt/proof/pip-report.json waveframe-guard==0.19.0 governance-ledger==0.9.0 cricore-contract-compiler==0.5.0 mcp==2.2.0 pytest==9.0.2
COPY examples/codex_connection/writer.py /opt/proof/original_writer.py
COPY tests/fixtures/action_policy_release_v4/mixed /opt/proof/publication
COPY examples/codex_contained/entry.py examples/codex_contained/server.py examples/codex_contained/probe.py examples/codex_contained/squid.conf /opt/proof/contained/
RUN dpkg-query -W > /opt/proof/os-packages.txt && pip freeze --all > /opt/proof/python-packages.txt
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 10001:10001
WORKDIR /source
ENTRYPOINT ["python", "-I", "/opt/proof/contained/entry.py"]
