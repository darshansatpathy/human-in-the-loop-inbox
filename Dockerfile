# syntax=docker/dockerfile:1
FROM python:3.15-slim AS build
WORKDIR /src
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir build && python -m build --wheel --outdir /dist

FROM python:3.15-slim
RUN useradd --system --uid 10001 --home /app hitl && mkdir -p /app
COPY --from=build /dist /dist
RUN pip install --no-cache-dir /dist/*.whl && rm -rf /dist
COPY policy.yaml /app/policy.yaml
USER 10001
WORKDIR /app
ENV PYTHONUNBUFFERED=1 HITL_POLICY_FILE=/app/policy.yaml
EXPOSE 8000
HEALTHCHECK --interval=10s --timeout=3s CMD python -c "import urllib.request,sys; sys.exit(urllib.request.urlopen('http://127.0.0.1:8000/healthz').status != 200)"
ENTRYPOINT ["hitl"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8000"]
