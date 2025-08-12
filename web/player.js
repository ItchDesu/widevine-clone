async function loadAndPlay(videoElement, contentId) {
  const licenseResp = await fetch('http://localhost:8080/license?content_id=' + encodeURIComponent(contentId), {method:'POST'});
  const keyBuf = await licenseResp.arrayBuffer();
  const key = keyBuf.slice(0,16);
  const iv = keyBuf.slice(16,32);

  const encResp = await fetch('encrypted.mp4');
  const encData = await encResp.arrayBuffer();

  const cryptoKey = await crypto.subtle.importKey('raw', key, {name:'AES-CTR'}, false, ['decrypt']);
  const decrypted = await crypto.subtle.decrypt({name:'AES-CTR', counter:new Uint8Array(iv), length:128}, cryptoKey, encData);

  const blob = new Blob([decrypted], {type:'video/mp4'});
  videoElement.src = URL.createObjectURL(blob);
}
