# CyberRock Examples

Every example here is **self-contained**. Pick the one closest to what you need, copy it into your project, and replace the block marked `YOUR INTEGRATION POINT`. Nothing else is required beyond the four core modules.

Filenames are unchanged from previous releases — only the folders are new.

---

## I want to…

| I want to… | Open this folder | Start with |
| --- | --- | --- |
| Check my wiring and see the token respond | [`01-getting-started/`](01-getting-started/) | `token_id.py` |
| Confirm the token hardware is healthy | [`01-getting-started/`](01-getting-started/) | `bist.py` |
| Bind a new token to my tenant account | [`01-getting-started/`](01-getting-started/) | `token_claim.py` |
| **Prove a device is genuine** | [`02-prove-device-identity/`](02-prove-device-identity/) | **`host_auth_priority.py`** |
| Prove the *cloud* is genuine too | [`02-prove-device-identity/`](02-prove-device-identity/) | `mutual_auth_host.py` |
| Get a session key both sides share | [`03-derive-session-key/`](03-derive-session-key/) | `host_auth_ek_priority.py` |
| …and never expose it in transit | [`03-derive-session-key/`](03-derive-session-key/) | `host_auth_ek_priority_rsa2048.py` |
| Tag my own data with the hardware | [`04-sign-and-verify-data/`](04-sign-and-verify-data/) | `hrwrequest_priority.py` |
| Prove which firmware actually booted | [`05-attest-boot-chain/`](05-attest-boot-chain/) | `secureboot_host.py` |
| Cover a batch of items with one check | [`06-chain-multiple-items/`](06-chain-multiple-items/) | `daisychain.py` |

**If you only read one:** `02-prove-device-identity/host_auth_priority.py`. It is the shortest complete round-trip and the pattern most integrations start from.

---

## Reading the filenames

Folders say *what you are trying to achieve*. Filenames follow the SDK's original scheme:

```text
<flow>_<variant>.py
```

**Flow** — who issues the challenge, and what is being proven:

| Flow | Meaning |
| --- | --- |
| `token_auth` | The **cloud** issues the challenge (CW → RW). Verification is driven server-side. |
| `host_auth` | The **device** issues the challenge (HCW → HRW). The device decides when to prove itself. |
| `mutual_auth` | Both sides prove themselves — the cloud returns an HRW2 the device can reproduce. |
| `hrwrequest` | Ask the cloud to derive the HRW for data you supply. |
| `secureboot` | Attest a chain of firmware hashes. |
| `daisychain` | Bind several data items to one verification. |

**Variant** — one or more suffixes, always in this order:

| Suffix | Meaning |
| --- | --- |
| `_ek` | Also derives an Ephemeral Key — a session key both sides compute but never transmit. |
| `_priority` | Synchronous. One call, immediate answer, no polling. Without it the flow polls for a result. |
| `_rsa2048` | The EK comes back RSA-2048 wrapped, not readable in transit. Requires `cryptography`. |
| `_host` | The host/device-initiated form of a chain or mutual flow. |
| `_hrw` | The cloud computes what the result *should* be, instead of grading one you submit. |

So `03-derive-session-key/host_auth_ek_priority_rsa2048.py` = device-initiated, derives a session key, answers immediately, key encrypted end to end.

---

## Quickstart

1. **Add your credentials** — fill in `SandGrain_Credentials.py`. See [`../docs/configuration.md`](../docs/configuration.md). Contact <support@sandgrain.eu> if you do not have a tenant account yet.
2. **Set your interface** — in `CyberRock_Config.py`, choose `'USB'` or `'SPI'` and pick the environment (`sandbox` or `production`).
3. **Confirm the token responds:**

   ```bash
   python examples/01-getting-started/token_id.py
   ```

   You should see a 64-character TID.
4. **Run your first full round-trip:**

   ```bash
   python examples/02-prove-device-identity/host_auth_priority.py
   ```

   You should see `AUTH_OK`. If you see `CLAIM_TOKEN`, run `01-getting-started/token_claim.py` first — the token is genuine but not yet bound to your tenant.

Requirements: Python 3.9+, `requests`, `pyserial`. The `_rsa2048` examples additionally need `cryptography`.

---

## Also here

- **A README in every folder** — what those scripts are for, a table for choosing between the variants, and a sequence diagram per script showing the Token ↔ Host ↔ Cloud exchange. Open the folder's README before opening the code.
- [`../docs/configuration.md`](../docs/configuration.md) — hardware wiring, interface selection, credentials.
- [`../docs/known-issues.md`](../docs/known-issues.md) — **read before copying** `06-chain-multiple-items/daisychain_host.py` or `05-attest-boot-chain/secureboot_hrw.py`.

---

## What changed from previous releases

**Filenames and behaviour are unchanged.** Every script issues exactly the same protocol calls, in the same order, with the same arguments as before. This was verified mechanically at migration time by `scripts/verify_migration.py`, which AST-compared all 27 old/new pairs and reported no differences. That script is retained for reference; it needs the pre-restructure sources on disk to run, and those have since been removed.

What moved is the location. All 27 previously lived in the flat `CyberRockCoreFunctions/` directory, which is gone; they now sit in six folders named for the outcome they achieve:

| Now in | Files |
| --- | --- |
| `examples/01-getting-started/` | `token_id.py` · `bist.py` · `token_claim.py` |
| `examples/02-prove-device-identity/` | `token_auth.py` · `host_auth.py` · `host_auth_priority.py` · `host_auth_hrwrequest.py` · `mutual_auth.py` · `mutual_auth_host.py` |
| `examples/03-derive-session-key/` | `token_auth_ek.py` · `token_auth_ek_rsa2048.py` · `host_auth_ek.py` · `host_auth_ek_rsa2048.py` · `host_auth_ek_priority.py` · `host_auth_ek_priority_rsa2048.py` |
| `examples/04-sign-and-verify-data/` | `hrwrequest.py` · `hrwrequest_priority.py` · `hrwrequest_ek.py` · `hrwrequest_ek_priority.py` · `hrwrequest_ek_rsa2048.py` · `hrwrequest_ek_priority_rsa2048.py` |
| `examples/05-attest-boot-chain/` | `secureboot.py` · `secureboot_host.py` · `secureboot_hrw.py` |
| `examples/06-chain-multiple-items/` | `daisychain.py` · `daisychain_host.py` · `daisychain_hrw.py` |

Watch for one split: the `host_auth` family lands in **two** folders. The plain, `_priority` and `_hrwrequest` forms prove device identity (folder 02); the `_ek` forms derive a session key (folder 03).

Two helpers were also lifted out of the scripts into `CyberRock_Token.py`, where they are now shared rather than copy-pasted 27 times: `hex_to_bytes()` (previously a per-file `strToList`) and `make_challenge()` (previously an inline timestamp-SHA256 block).
