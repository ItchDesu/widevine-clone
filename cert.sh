#!/usr/bin/env bash
set -euo pipefail

# =========================
# Config por defecto
# =========================
OUTDIR="${OUTDIR:-tls}"
CA_CN="${CA_CN:-Buzzster Local Root}"
CA_O="${CA_O:-Buzzster Dev CA}"
SRV_CN="${SRV_CN:-localhost}"
SRV_O="${SRV_O:-Buzzster Dev}"
DAYS_CA="${DAYS_CA:-3650}"
DAYS_SRV="${DAYS_SRV:-825}"
# SANs por defecto: localhost + loopbacks
SANS="${SANS:-DNS:localhost,IP:127.0.0.1,IP:::1}"

mkdir -p "$OUTDIR"
cd "$OUTDIR"

echo "==> Generando CA sin password..."
# Clave y cert de CA (sin passphrase)
openssl genrsa -out ca.key 4096 >/dev/null 2>&1
openssl req -x509 -new -key ca.key -sha256 -days "$DAYS_CA" \
  -subj "/C=ES/O=$CA_O/CN=$CA_CN" \
  -out ca.crt >/dev/null 2>&1

chmod 600 ca.key

echo "==> Generando clave del servidor..."
openssl genrsa -out server.key 2048 >/dev/null 2>&1
chmod 600 server.key

# Config de CSR con SAN (no interactivo)
cat > san.cnf <<EOF
[ req ]
default_bits        = 2048
prompt              = no
default_md          = sha256
req_extensions      = req_ext
distinguished_name  = dn

[ dn ]
C  = ES
O  = $SRV_O
CN = $SRV_CN

[ req_ext ]
subjectAltName = @alt_names

[ alt_names ]
$(# expandir SANS en líneas DNS.N/IP.N
i=1
IFS=',' read -ra items <<< "$SANS"
for it in "${items[@]}"; do
  k="${it%%:*}"
  v="${it#*:}"
  if [[ "$k" == "DNS" ]]; then
    echo "DNS.$i = $v"
    ((i++))
  fi
done
j=1
for it in "${items[@]}"; do
  k="${it%%:*}"
  v="${it#*:}"
  if [[ "$k" == "IP" ]]; then
    echo "IP.$j = $v"
    ((j++))
  fi
done
)
EOF

echo "==> Creando CSR con SAN..."
openssl req -new -key server.key -out server.csr -config san.cnf >/dev/null 2>&1

# Extensiones para el certificado final
cat > v3.ext <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
$(# repetir mapeo para x509 -extfile
i=1
IFS=',' read -ra items <<< "$SANS"
for it in "${items[@]}"; do
  k="${it%%:*}"
  v="${it#*:}"
  if [[ "$k" == "DNS" ]]; then
    echo "DNS.$i = $v"
    ((i++))
  fi
done
j=1
for it in "${items[@]}"; do
  k="${it%%:*}"
  v="${it#*:}"
  if [[ "$k" == "IP" ]]; then
    echo "IP.$j = $v"
    ((j++))
  fi
done
)
EOF

echo "==> Firmando certificado del servidor con la CA..."
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -days "$DAYS_SRV" -sha256 -extfile v3.ext >/dev/null 2>&1

cat server.crt ca.crt > server.fullchain.crt

echo "==> Generando clave de firma de licencias y pública SPKI..."
# Clave separada para firma de licencias (recomendado)
openssl genrsa -out license_signing.key 2048 >/dev/null 2>&1
chmod 600 license_signing.key
# Pública SPKI para /public_key
openssl pkey -in license_signing.key -pubout -out public.pem >/dev/null 2>&1

# (Opcional) si quieres usar la misma clave del server para licencias, comenta lo de arriba
# y descomenta la siguiente línea:
# openssl pkey -in server.key -pubout -out public.pem >/dev/null 2>&1

echo ""
echo "==> Hecho."
echo "Archivos en $(pwd):"
ls -1 ca.crt ca.key server.key server.csr server.crt server.fullchain.crt license_signing.key public.pem | sed 's/^/  - /'

echo ""
echo "==> Importa ca.crt en tu sistema/navegador para evitar warnings."
echo ""
echo "==> Exports listos para tu binario:"
cat <<ENV

export API_TOKEN=your_token
export CERT_FILE=$(pwd)/server.crt
export KEY_FILE=$(pwd)/server.key
export PUBLIC_KEY_FILE=$(pwd)/public.pem
# Recomendado:
export LICENSE_SIGNING_KEY=$(pwd)/license_signing.key

# Ejemplo de arranque:
# \$API_TOKEN \$CERT_FILE \$KEY_FILE \$PUBLIC_KEY_FILE \$LICENSE_SIGNING_KEY ./license_cerver

ENV
