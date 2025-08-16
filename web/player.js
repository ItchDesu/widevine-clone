function toHex(buffer) {
  const bytes = new Uint8Array(buffer);
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// --- utilidades base64 robustas ---
function b64Normalize(b64) {
  // quita todo lo que no sea base64/url-safe o '='
  let s = b64.replace(/[^A-Za-z0-9_\-+/=]/g, '');
  // convierte url-safe -> estándar
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  // relleno '='
  const pad = s.length % 4;
  if (pad) s += '='.repeat(4 - pad);
  return s;
}
function b64DecodeToBytes(b64) {
  const s = b64Normalize(b64);
  return Uint8Array.from(atob(s), c => c.charCodeAt(0));
}

// Acepta PUBLIC KEY o CERTIFICATE; si te llega un cert, seguirá fallando en importKey (SPKI requerido)
function b64FromPem(pem) {
  return pem
    .replace(/-----BEGIN [^-]+-----/g, '')
    .replace(/-----END [^-]+-----/g, '')
    .replace(/\s+/g, '');
}

async function importPublicKey(pem) {
  const b64 = b64FromPem(pem);
  const der = b64DecodeToBytes(b64);
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
    body: JSON.stringify({ content_id: String(contentId) })
  });

  if (!licenseResp.ok) {
    throw new Error(`License server error: ${licenseResp.status}`);
  }

  const { license, expiry, signature } = await licenseResp.json();
  if (typeof license !== 'string' || typeof signature !== 'string') {
    throw new Error('Bad license payload');
  }

  // cache-bust del PEM por si el navegador lo cachea
  const publicKeyPem = await fetch(`https://localhost:8443/public_key?v=${Date.now()}`, {
    cache: 'no-store'
  }).then(r => r.text());
  const publicKey = await importPublicKey(publicKeyPem);

  const enc = new TextEncoder();
  const payload = enc.encode(String(contentId) + String(expiry) + String(license));

  const sigBytes = b64DecodeToBytes(signature);

  const valid = await crypto.subtle.verify(
    { name: 'RSASSA-PKCS1-v1_5' },
    publicKey,
    sigBytes,
    payload
  );
  if (!valid) {
    // Debug opcional: imprime hash de payload para comparar con el servidor
    const hash = await crypto.subtle.digest('SHA-256', payload);
    console.error('[verify] payload.sha256=', toHex(hash));
    throw new Error('Invalid license signature');
  }

  if ((Date.now() / 1000) > Number(expiry)) {
    throw new Error('License expired');
  }

  const keyBytes = b64DecodeToBytes(license);
  if (keyBytes.length < 32) {
    throw new Error('License payload too short (need at least 32 bytes for key+iv)');
  }
  const key = keyBytes.slice(0, 16);
  const iv  = keyBytes.slice(16, 32);

  const encResp = await fetch('encrypted.mp4', { cache: 'no-store' });
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