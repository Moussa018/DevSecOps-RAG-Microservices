FROM python:3.12-slim AS build
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt
RUN PYTHONPATH=/install/lib/python3.12/site-packages python -c "from fastembed import TextEmbedding; TextEmbedding(model_name='sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2', cache_dir='/models')" && chmod -R a+rX /models

FROM python:3.12-slim
RUN useradd -u 65532 -r -s /usr/sbin/nologin app
COPY --from=build /install /usr/local
COPY --from=build /models /models
ENV HF_HUB_OFFLINE=1 FASTEMBED_CACHE_PATH=/models HF_HOME=/tmp/hf
WORKDIR /app
COPY app.py llm.py auth.py svc_client.py ./
USER 65532
EXPOSE 8000
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000", "--no-server-header", "--ssl-keyfile", "/tls/tls.key", "--ssl-certfile", "/tls/tls.crt", "--ssl-ca-certs", "/tls/ca.crt", "--ssl-cert-reqs", "2"]
