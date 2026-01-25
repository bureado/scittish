FROM python:3.12-slim

WORKDIR /app

# Install pyscitt dependencies first (these are heavier)
# These match pyscitt's setup.py requirements
RUN pip install --no-cache-dir \
    ccf==6.* \
    cryptography==44.* \
    httpx \
    cbor2==5.8.* \
    pycose==1.1.0 \
    pyjwt \
    jwcrypto==1.5.* \
    azure-identity \
    azure-confidentialledger==1.* \
    loguru

# Copy pyscitt module
COPY pyscitt/pyscitt /app/pyscitt

# Install API dependencies
COPY api/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY api/app.py api/certs.py ./

# Create directories for certs and cache
RUN mkdir -p /var/cache/scittish /var/lib/scittish/certs

ENV SCITT_CACHE_DIR=/var/cache/scittish
ENV SCITT_CERTS_DIR=/var/lib/scittish/certs
ENV SCITT_URL=https://localhost:8000
ENV PYTHONPATH=/app

EXPOSE 8080

CMD ["gunicorn", "--bind", "0.0.0.0:8080", "app:app"]
