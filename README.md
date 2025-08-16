# Simple DRM Demo

This repository contains a minimal example of a DRM-like workflow using C++ for
content encryption and a license server, plus client code that fetches a key and
decrypts video. The server runs over **HTTPS**, validates JSON input with
`nlohmann::json`, signs licenses using an RSA key and enforces a basic token
authentication and per-IP rate limit. Responses include a base64-encoded license
and an expiration timestamp, together with a signature that clients verify using
the server's public key.

## Build

```
# encrypt video
g++ -std=c++17 src/encrypt_video.cpp -lcrypto -o encrypt_video
./encrypt_video input.mp4 encrypted.mp4 sample.key

# generate self-signed certificate and public key
openssl req -x509 -newkey rsa:2048 -nodes -keyout server.key -out server.crt -subj "/CN=localhost"
openssl rsa -in server.key -pubout -out public.pem

# build and start license server (serves `sample.key` for `content_id=sample`)
g++ -std=c++17 src/license_server.cpp -Iinclude -pthread -lssl -lcrypto -o license_server
API_TOKEN=your_token CERT_FILE=server.crt KEY_FILE=server.key PUBLIC_KEY_FILE=public.pem ./license_server
```

The license server responds with JSON containing the encrypted key, an
expiration time (seconds since epoch) and an RSA-SHA256 signature to allow
clients to verify integrity:

```json
{"license":"...","expiry":1700000000,"signature":"<hex>"}
```

## Web demo

Serve the `web/` directory (for example with `python3 -m http.server`), and
open `index.html` in a browser. Enter the token configured in `API_TOKEN` and
press **Play**. The client fetches the server's public key, verifies the
signature and decrypts `encrypted.mp4` for playback.

## Mobile SDKs

The `sdk/` directory contains simple clients for requesting licenses from the
demo server:

- `sdk/kotlin` provides a Kotlin helper suitable for Android projects.
- `sdk/dart` provides a Dart helper for Flutter applications.

This code is for educational purposes and omits many production considerations
that real DRM systems like Widevine include.
