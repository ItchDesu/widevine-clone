const SHARED_SECRET = 'demo_secret'; // ← igual que el servidor

function toHex(buffer) {
  const bytes = new Uint8Array(buffer);
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function loadAndPlay(videoElement, contentId) {
  const licenseResp = await fetch('http://localhost:8080/license', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ content_id: contentId })
  });

  if (!licenseResp.ok) {
    throw new Error(`License server error: ${licenseResp.status}`);
  }

  const { license, expiry, signature } = await licenseResp.json();

  // Recalcular el HMAC tal y como hace el servidor: cid + expiry + license
  const enc = new TextEncoder();
  const hmacKey = await crypto.subtle.importKey(
    'raw',
    enc.encode(SHARED_SECRET),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  const payload = enc.encode(String(contentId) + String(expiry) + String(license));
  const mac = await crypto.subtle.sign('HMAC', hmacKey, payload);
  const expectedSigHex = toHex(mac); // ← comparar en HEX

  if (signature !== expectedSigHex) {
    throw new Error('Invalid license signature');
  }
  if (Date.now() / 1000 > Number(expiry)) {
    throw new Error('License expired');
  }

  // Decodificar licencia y extraer key/iv
  const keyBytes = Uint8Array.from(atob(license), c => c.charCodeAt(0));
  if (keyBytes.length < 32) {
    throw new Error('License payload too short (need at least 32 bytes for key+iv)');
  }
  const key = keyBytes.slice(0, 16);
  const iv  = keyBytes.slice(16, 32);

  // Descargar y descifrar
  const encResp = await fetch('encrypted.mp4'); // asegúrate de CORS si no es same-origin
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