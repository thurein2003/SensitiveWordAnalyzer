FROM python:3.13-slim AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /build
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN python -m pip wheel --no-deps --wheel-dir /wheels .

FROM python:3.13-slim

LABEL org.opencontainers.image.title="Sensitive Word Analyzer" \
      org.opencontainers.image.description="Read-only static triage for suspicious files" \
      org.opencontainers.image.source="https://github.com/thurein2003/SensitiveWordAnalyzer" \
      org.opencontainers.image.licenses="MIT"

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN groupadd --system scanner \
    && useradd --system --gid scanner --create-home scanner
COPY --from=builder /wheels /wheels
RUN python -m pip install /wheels/*.whl \
    && rm -rf /wheels

USER scanner
WORKDIR /scan
ENTRYPOINT ["swa"]
CMD ["--help"]
