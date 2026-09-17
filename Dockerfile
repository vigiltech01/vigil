# ---- front-end libraries (pinned versions, checksum-verified) ------------------------------------------------------
FROM python:3.12-slim AS vendor
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /vendor
COPY docker/vendor.sha256 /tmp/vendor.sha256
RUN set -eux; \
    mkdir -p three; \
    curl -fsSL -o echarts.min.js https://cdn.jsdelivr.net/npm/echarts@5.5.1/dist/echarts.min.js; \
    T=https://cdn.jsdelivr.net/npm/three@0.147.0; \
    curl -fsSL -o three/three.min.js "$T/build/three.min.js"; \
    for f in controls/OrbitControls shaders/CopyShader shaders/LuminosityHighPassShader postprocessing/EffectComposer \
             postprocessing/RenderPass postprocessing/ShaderPass postprocessing/MaskPass postprocessing/UnrealBloomPass; do \
        curl -fsSL -o "three/$(basename "$f").js" "$T/examples/js/$f.js"; \
    done; \
    sha256sum -c /tmp/vendor.sha256

# ---- application ---------------------------------------------------------------------------------------------------
FROM python:3.12-slim
LABEL org.opencontainers.image.title="Vigil" \
      org.opencontainers.image.description="FortiGate syslog dashboard: live threats, inbound rule risk, investigations" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/vigiltech01/vigil"
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 VIGIL_DATA=/data
RUN useradd --system --uid 10001 --home-dir /app --shell /usr/sbin/nologin vigil
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY vigil ./vigil
COPY web ./web
COPY --from=vendor /vendor ./web/static/vendor
RUN mkdir -p /data && chown vigil:vigil /data
USER vigil
EXPOSE 8080 5514/udp 5514/tcp
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=4)"
ENTRYPOINT ["python", "-m", "vigil"]
