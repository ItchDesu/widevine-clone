// ======= Config =======
const SERVER = 'https://localhost:8443';
const DEBUG = false;

// ======= Utils =======
function toHex(buffer) {
  const bytes = new Uint8Array(buffer);
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// Base64 robusto (acepta url-safe y rellena '=')
function b64Normalize(b64) {
  let s = String(b64).replace(/[^A-Za-z0-9_\-+/=]/g, '');
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  const pad = s.length % 4;
  if (pad) s += '='.repeat(4 - pad);
  return s;
}
function b64DecodeToBytes(b64) {
  const s = b64Normalize(b64);
  return Uint8Array.from(atob(s), c => c.charCodeAt(0));
}

// Extrae cuerpo base64 de un PEM (PUBLIC KEY o CERTIFICATE)
// *Tu servidor ya devuelve PUBLIC KEY (SPKI), perfecto para importKey('spki')
function b64FromPem(pem) {
  return pem.replace(/-----BEGIN [^-]+-----/g, '')
            .replace(/-----END [^-]+-----/g, '')
            .replace(/\s+/g, '');
}

async function importPublicKeyFromPem(pem) {
  const der = b64DecodeToBytes(b64FromPem(pem));
  return crypto.subtle.importKey(
    'spki',
    der.buffer,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['verify']
  );
}

function withTimeout(ms) {
  const ctrl = new AbortController();
  const id = setTimeout(() => ctrl.abort('timeout'), ms);
  return { signal: ctrl.signal, cancel: () => clearTimeout(id) };
}

// ======= Flujo principal =======
export async function loadAndPlay(videoElement, contentId, token) {
  // 1) Pide licencia (POST /license)
  const t1 = withTimeout(10000);
  const licenseResp = await fetch(`${SERVER}/license`, {
    method: 'POST',
    mode: 'cors',
    cache: 'no-store',
    signal: t1.signal,
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`
    },
    body: JSON.stringify({ content_id: String(contentId) })
  }).finally(t1.cancel);

  if (!licenseResp.ok) {
    throw new Error(`License server error: ${licenseResp.status}`);
  }

  const { license, expiry, signature } = await licenseResp.json();
  if (typeof license !== 'string' || typeof signature !== 'string' || typeof expiry !== 'number') {
    throw new Error('Bad license payload');
  }

  // 2) Descarga la pública SPKI (GET /public_key)
  const t2 = withTimeout(8000);
  const publicKeyPem = await fetch(`${SERVER}/public_key?v=${Date.now()}`, {
    method: 'GET',
    mode: 'cors',
    cache: 'no-store',
    signal: t2.signal,
  }).then(r => r.text()).finally(t2.cancel);

  // Importa como SPKI (RSA)
  const publicKey = await importPublicKeyFromPem(publicKeyPem);

  // 3) Verificación firma: payload EXACTO = cid + expiry + license (tal cual)
  const enc = new TextEncoder();
  const payloadText = String(contentId) + String(expiry) + String(license);
  const payload = enc.encode(payloadText);
  const sigBytes = b64DecodeToBytes(signature);

  const valid = await crypto.subtle.verify(
    { name: 'RSASSA-PKCS1-v1_5' },
    publicKey,
    sigBytes,
    payload
  );

  if (!valid) {
    if (DEBUG) {
      const hash = await crypto.subtle.digest('SHA-256', payload);
      console.error('[verify] payload.sha256=', toHex(hash));
      console.error('[verify] pub first line=', publicKeyPem.split('\n')[0]);
    }
    throw new Error('Invalid license signature');
  }

  // 4) Expiración
  if ((Date.now() / 1000) > Number(expiry)) {
    throw new Error('License expired');
  }

  // 5) Extrae key||iv (16+16) de license (base64 estándar)
  const keyBytes = b64DecodeToBytes(license);
  if (keyBytes.length < 32) {
    throw new Error('License payload too short (need >= 32 bytes)');
  }
  const key = keyBytes.slice(0, 16);
  const iv  = keyBytes.slice(16, 32);

  // 6) Descarga y descifra el media (AES-CTR con iv de 16 bytes)
  const t3 = withTimeout(15000);
  const encResp = await fetch('encrypted.mp4', {
    method: 'GET',
    mode: 'cors',
    cache: 'no-store',
    signal: t3.signal
  }).finally(t3.cancel);
  if (!encResp.ok) throw new Error(`Encrypted media error: ${encResp.status}`);
  const encData = await encResp.arrayBuffer();

  const cryptoKey = await crypto.subtle.importKey('raw', key, { name: 'AES-CTR' }, false, ['decrypt']);
  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-CTR', counter: iv, length: 128 },
    cryptoKey,
    encData
  );

  // 7) Reproduce
  const blob = new Blob([decrypted], { type: 'video/mp4' });
  videoElement.src = URL.createObjectURL(blob);
  if (DEBUG) console.log('[play] ready, size=', decrypted.byteLength);
}