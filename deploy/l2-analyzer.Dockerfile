FROM python:3.11-slim@sha256:e031123e3d85762b141ad1cbc56452ba69c6e722ebf2f042cc0dc86c47c0d8b3

RUN groupadd --gid 65532 analyzer \
    && useradd --uid 65532 --gid 65532 --no-create-home --home-dir /nonexistent analyzer

COPY deploy/l2-analyzer-requirements.txt /opt/l2-analyzer-requirements.txt
RUN pip install --no-cache-dir --require-hashes -r /opt/l2-analyzer-requirements.txt

COPY --chown=65532:65532 tools/l2_analyzer.py /opt/l2_analyzer.py
COPY --chown=65532:65532 ditto_screener/data/starter-kit-provenance-*.json /opt/starter-manifests/

USER 65532:65532
WORKDIR /scratch
ENTRYPOINT ["python3", "-I", "/opt/l2_analyzer.py"]
