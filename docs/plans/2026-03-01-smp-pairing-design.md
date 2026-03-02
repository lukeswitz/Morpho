# Design: SMP Pairing Vulnerability Scanner (S13) + S8 Auth Escalation

**Date:** 2026-03-01
**Approach:** A — New S13 stage + S8 inline retry

---

## S13 — Pairing Vulnerability Scanner

Connects to each connectable target and walks a pairing matrix from weakest to
strongest. Records which modes the target accepts without user interaction.

### Pairing matrix

| # | Mode | Pairing() params | Severity if accepted |
|---|------|-----------------|----------------------|
| 1 | LESC Just Works | `lesc=True, mitm=False, bonding=False` | high |
| 2 | Legacy Just Works | `lesc=False, mitm=False, bonding=False` | critical |
| 3 | LESC + Bonding | `lesc=True, mitm=False, bonding=True` | high |
| 4 | Legacy + Bonding | `lesc=False, mitm=False, bonding=True` | critical |

Keys (LTK, IRK, CSRK) captured when bonding succeeds.

### Findings

- `pairing_no_mitm` — accepted without MITM protection
- `pairing_legacy_accepted` — accepts legacy (pre-4.2) downgrade
- `pairing_keys_captured` — bonding succeeded, keys in evidence

### Gate

`target.connectable`, no gatt_profile dependency, capability `can_central`.

---

## S8 Auth Escalation

After the existing write phase, if any result has `error == "auth_required"`:
1. Attempt LESC Just Works pairing inline on the same connection
2. Retry only the rejected handles
3. Store results in `evidence["post_pairing_results"]`
4. Escalate severity to `high` if any retry succeeds

---

## Files

| File | Change |
|------|--------|
| `stages/s13_pairing.py` | New stage |
| `stages/s8_poc.py` | Add post-pairing retry loop |
| `main.py` | Add S13 gate |
| `config.py` | Add `S13_PAIRING_TIMEOUT`, `S13_CONNECT_TIMEOUT` |
