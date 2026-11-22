FROM python:3.12-slim AS build
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM python:3.12-slim
RUN useradd -u 65532 -r -s /usr/sbin/nologin app
COPY --from=build /install /usr/local
WORKDIR /app
COPY *.py ./
USER 65532
EXPOSE 8000
# TLS mutuel : le serveur exige un certificat client signe par la CA privee (--ssl-cert-reqs 2 = CERT_REQUIRED)
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000", "--no-server-header", "--ssl-keyfile", "/tls/tls.key", "--ssl-certfile", "/tls/tls.crt", "--ssl-ca-certs", "/tls/ca.crt", "--ssl-cert-reqs", "2"]
