# Verify AI Attestation (GitHub Action)

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
