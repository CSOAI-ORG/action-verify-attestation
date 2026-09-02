# Verify AI Attestation (GitHub Action)

[![22 axes measured · 14 model fleets · 3 public leader scores · 8 fact runs · TIE is TIE · not a certificate. Three states only: VALID · INVALID · UNCHECKABLE.](https://councilof.ai/badge/gspc.svg)](https://councilof.ai/gspc-verify)

Zero-dependency CI verification of Council of AI signed attestations (Ed25519,
canonical content_id). Works on any signed artifact (`/signed/*`, `/signals/*`,
`/interop/*` from councilof.ai).

```yaml
- uses: CSOAI-ORG/action-verify-attestation@v1
  with:
    artifact: public/signed/board_living.json
```

Fails the job if the signature is invalid or the canonical changed. Verification is
free forever; measurement, not certification.
