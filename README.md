# Simple DRM Demo

This repository contains a minimal example of a DRM-like workflow using C++ for
content encryption and a license server, plus client code that fetches a key and
decrypts video. The license server accepts a JSON request containing a
`content_id` and responds with a base64-encoded license similar to real DRM
systems such as Widevine. The demo server now validates `content_id` values,
includes an expiration timestamp and an HMAC-SHA256 signature in its responses
to better illustrate how real-world systems secure licenses.

## Build

```
# encrypt video
g++ -std=c++17 src/encrypt_video.cpp -lcrypto -o encrypt_video
./encrypt_video input.mp4 encrypted.mp4 sample.key

# start license server (serves `sample.key` for `content_id=sample`)
g++ -std=c++17 src/license_server.cpp -Iinclude -pthread -lssl -lcrypto -o license_server
./license_server
```

The license server responds with JSON containing the encrypted key, an
expiration time (seconds since epoch) and an `HMAC-SHA256` signature to allow
clients to verify integrity:

```json
{"license":"...","expiry":1700000000,"signature":"<hex>"}
```

## Web demo

Serve the `web/` directory (for example with `python3 -m http.server`), and
open `index.html` in a browser. It will request the key from the license server
and decrypt `encrypted.mp4` for playback.

## Mobile SDKs

The `sdk/` directory contains simple clients for requesting licenses from the
demo server:

- `sdk/kotlin` provides a Kotlin helper suitable for Android projects.
- `sdk/dart` provides a Dart helper for Flutter applications.

This code is for educational purposes and omits many production considerations
that real DRM systems like Widevine include.
