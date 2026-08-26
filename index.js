// Verify AI Attestation — zero-dep Ed25519 checker (style-A board / style-B signal-card).
// Canonical per estate spec; verify_signed.py equivalent in Node (WebCrypto).
const { createPublicKey, verify } = require("node:crypto");
const fs = require("node:fs");

function canon(obj, compact) {
  return JSON.stringify(obj, compact
    ? Object.create(null)
    : null);
}
function styled(compact) { return (o) => { if (compact) { const r={}; for (const k of Object.keys(o).sort()) r[k]=o[k]; return r; } return o; }; }

async function main() {
  const p = process.env["INPUT_ARTIFACT"];
  if (!p) { console.error("artifact input required"); process.exit(2); }
  const d = JSON.parse(fs.readFileSync(p, "utf8"));
  let ok = false;
  if (typeof d.signature === "string") {
    // style-A: sha256(canonical minus sig fields, default separators) -> Ed25519
    const body = {}; for (const k of Object.keys(d)) if (!["signature","signer","signed","sig_input"].includes(k)) body[k]=d[k];
    const digest = crypto_bundle.sha256(JSON.stringify(body));
    ok = await ed25519(d.signer, d.signature, digest);
  } else if (d.signature && d.signature.pubkey) {
    const body = {}; for (const k of Object.keys(d)) if (!["content_id","signature"].includes(k)) body[k]=d[k];
    const canonB = JSON.stringify(JSON.parse(JSON.stringify(body, null, 0)), Object.keys(body).sort());
    ok = await ed25519(d.signature.pubkey, d.signature.sig, crypto_bundle.sha256(canonB));
  }
  console.log(ok ? "ATTESTATION VALID" : "ATTESTATION INVALID");
  process.exit(ok ? 0 : 1);
}
const crypto_bundle = { sha256: (s) => require("node:crypto").createHash("sha256").update(s).digest() };
async function ed25519(pubHex, sigB64orHex, message) {
  const crypto = require("node:crypto");
  const raw = Buffer.from(pubHex, "hex");
  const spki = Buffer.concat([Buffer.from("302a300506032b6570032100","hex"), raw]);
  const key = createPublicKey({ key: spki, format: "der", type: "spki" });
  const sig = Buffer.from(sigB64orHex.length===64? sigB64orHex : sigB64orHex, sigB64orHex.length===64?"hex":"base64");
  return verify("ed25519", key, sig, message);
}
main();
