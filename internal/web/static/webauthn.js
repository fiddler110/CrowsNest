// WebAuthn helpers shared by the sign-in and Account pages. The server speaks base64url JSON; the browser wants
// ArrayBuffers, so these convert both ways.
const b64uToBuf = (s) => {
  const b = atob(s.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(s.length / 4) * 4, "="));
  return Uint8Array.from(b, (c) => c.charCodeAt(0)).buffer;
};
const bufToB64u = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)))
  .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

// Make a passkey from the server's creation options; returns the JSON the server expects back.
async function passkeyCreate(options) {
  const pk = options.publicKey;
  pk.challenge = b64uToBuf(pk.challenge);
  pk.user.id = b64uToBuf(pk.user.id);
  (pk.excludeCredentials || []).forEach((c) => { c.id = b64uToBuf(c.id); });
  const c = await navigator.credentials.create({ publicKey: pk });
  return JSON.stringify({
    id: c.id, rawId: bufToB64u(c.rawId), type: c.type,
    response: {
      attestationObject: bufToB64u(c.response.attestationObject),
      clientDataJSON: bufToB64u(c.response.clientDataJSON),
      transports: c.response.getTransports ? c.response.getTransports() : [],
    },
  });
}

// Sign a challenge with a passkey from the server's request options.
async function passkeyGet(options) {
  const pk = options.publicKey;
  pk.challenge = b64uToBuf(pk.challenge);
  (pk.allowCredentials || []).forEach((c) => { c.id = b64uToBuf(c.id); });
  const c = await navigator.credentials.get({ publicKey: pk });
  return JSON.stringify({
    id: c.id, rawId: bufToB64u(c.rawId), type: c.type,
    response: {
      authenticatorData: bufToB64u(c.response.authenticatorData),
      clientDataJSON: bufToB64u(c.response.clientDataJSON),
      signature: bufToB64u(c.response.signature),
      userHandle: c.response.userHandle ? bufToB64u(c.response.userHandle) : null,
    },
  });
}
