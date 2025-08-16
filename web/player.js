function toHex(buffer) {
  const bytes = new Uint8Array(buffer);
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function importPublicKey(pem) {
  const b64 = pem.replace(/-----BEGIN PUBLIC KEY-----/,'').replace(/-----END PUBLIC KEY-----/,'').replace(/\s+/g,'');
  const der = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  return crypto.subtle.importKey(
    'spki',
    der.buffer,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['verify']
  );
}

async function loadAndPlay(videoElement, contentId, token) {
  const licenseResp = await fetch('https://localhost:8443/license', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`
    },
    body: JSON.stringify({ content_id: contentId })
  });

  if (!licenseResp.ok) {
    throw new Error(`License server error: ${licenseResp.status}`);
  }

  const { license, expiry, signature } = await licenseResp.json();

  const publicKeyPem = await fetch('https://localhost:8443/public_key').then(r => r.text());
  const publicKey = await importPublicKey(publicKeyPem);

  const enc = new TextEncoder();
  const payload = enc.encode(String(contentId) + String(expiry) + String(license));
  const sigBytes = Uint8Array.from(atob(signature), c => c.charCodeAt(0));
  const valid = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', publicKey, sigBytes, payload);
  if (!valid) {
    throw new Error('Invalid license signature');
  }
  if (Date.now() / 1000 > Number(expiry)) {
    throw new Error('License expired');
  }

  const keyBytes = Uint8Array.from(atob(license), c => c.charCodeAt(0));
  if (keyBytes.length < 32) {
    throw new Error('License payload too short (need at least 32 bytes for key+iv)');
  }
  const key = keyBytes.slice(0, 16);
  const iv  = keyBytes.slice(16, 32);

  const encResp = await fetch('encrypted.mp4');
  if (!encResp.ok) throw new Error(`Encrypted media error: ${encResp.status}`);
  const encData = await encResp.arrayBuffer();

  const cryptoKey = await crypto.subtle.importKey('raw', key, { name: 'AES-CTR' }, false, ['decrypt']);
  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-CTR', counter: new Uint8Array(iv), length: 128 },
    cryptoKey,
    encData
  );

  const blob = new Blob([decrypted], { type: 'video/mp4' });
  videoElement.src = URL.createObjectURL(blob);
}
