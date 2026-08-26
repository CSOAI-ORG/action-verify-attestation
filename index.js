// Verify AI Attestation — zero-dep Ed25519 checker (style-A board / style-B signal-card).
// Estate canon: style-A = sha256(json.dumps(body, sort_keys=True (default separators)))
// -> Ed25519; style-B = sha256(json.dumps(body, sort_keys, compact, ensure_ascii=False))
// -> Ed25519. JS stringify = compact separators, keys MUST be sorted manually.
const crypto = require("node:crypto");
const fs = require("node:fs");

const SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

function sortedCopy(obj) {
  const out = {};
  for (const k of Object.keys(obj).sort()) out[k] = obj[k];
  return out;
}

function pyStyle(value, compact) {
  const esc = (t) => compact ? t : t.replace(/[\u0080-\uFFFF]/g,
    (c) => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0"));
  // python json.dumps(sort_keys=True) formatting: compact = separators (",", ":");
  // style-A default = separators (", ", ": ") — recursive, string-safe.
  if (value === null || typeof value !== "object") {
    return esc(JSON.stringify(value));
  }
  if (Array.isArray(value)) {
    const items = value.map((v) => pyStyle(v, compact));
    return "[" + items.join(compact ? "," : ", ") + "]";
  }
  const ks = Object.keys(value).sort();
  const parts = ks.map((k) => esc(JSON.stringify(k))
      + (compact ? ":" : ": ") + pyStyle(value[k], compact));
  return "{" + parts.join(compact ? "," : ", ") + "}";
}

function canon(obj, compact) {
  return pyStyle(obj, compact);
}

function sha256(s) {
  return crypto.createHash("sha256").update(s).digest();
}

function ed25519_verify(pubHex, sigBuf, msg) {
  const key = crypto.createPublicKey({
    key: Buffer.concat([SPKI_PREFIX, Buffer.from(pubHex, "hex")]),
    format: "der",
    type: "spki",
  });
  return crypto.verify(null, msg, key, sigBuf);
}

async function main() {
  const p = process.env["INPUT_ARTIFACT"];
  if (!p) { console.error("artifact input required"); process.exit(2); }
  const d = JSON.parse(fs.readFileSync(p, "utf8"));
  let ok = false;
  if (typeof d.signature === "string") {
    const body = {};
    for (const k of Object.keys(d)) {
      if (!["signature", "signer", "signed", "sig_input"].includes(k)) body[k] = d[k];
    }
    const c = canon(body, false);
    ok = ed25519_verify(d.signer, Buffer.from(d.signature, "hex"), sha256(c));
  } else if (d.signature && d.signature.pubkey) {
    const body = {};
    for (const k of Object.keys(d)) {
      if (!["content_id", "signature"].includes(k)) body[k] = d[k];
    }
    const c = canon(body, true);
    // style-B signs the ASCII hex string of content_id (sk.sign(cid.encode()))
    const cid = sha256(c).toString("hex");
    ok = ed25519_verify(Buffer.from(d.signature.pubkey, "base64").toString("hex"),
                        Buffer.from(d.signature.sig, "base64"), Buffer.from(cid, "utf8"));
  }
  console.log(ok ? "ATTESTATION VALID" : "ATTESTATION INVALID");
  process.exit(ok ? 0 : 1);
}

main().catch((e) => { console.error(e.message); process.exit(2); });
