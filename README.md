# Simple DRM Demo

This repository contains a minimal example of a DRM-like workflow using C++ for
content encryption and a license server, plus a browser script that fetches a
key and decrypts video using the Web Crypto API.

## Build

```
# encrypt video
g++ -std=c++17 src/encrypt_video.cpp -lcrypto -o encrypt_video
./encrypt_video input.mp4 encrypted.mp4 sample.key

# start license server (serves `sample.key` for content_id=sample)
g++ -std=c++17 src/license_server.cpp -Iinclude -pthread -lssl -lcrypto -o license_server
./license_server
```

## Web demo

Serve the `web/` directory (for example with `python3 -m http.server`), and
open `index.html` in a browser. It will request the key from the license server
and decrypt `encrypted.mp4` for playback.

This code is for educational purposes and omits many production considerations
that real DRM systems like Widevine include.
