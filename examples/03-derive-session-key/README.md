# 03 - Derive a Session Key

**Give me a symmetric key both sides hold but neither transmits.**

These are the folder 02 authentication flows with one addition: the token also emits a 16-byte **Ephemeral Key (EK)**, and the cloud's HSM derives the same value independently. Authentication and key establishment happen in one exchange, and the key itself never crosses the wire.

Always compare the two EKs before use. A mismatch means the sides disagree - do not fall back to using either.

| Script | Challenge from | Result | EK delivery | Cost |
| --- | --- | --- | --- | --- |
| [`host_auth_ek_priority.py`](host_auth_ek_priority.py) ⭐ | Device | Immediate | plaintext over HTTPS | 2 cloud calls |
| [`host_auth_ek_priority_rsa2048.py`](host_auth_ek_priority_rsa2048.py) 🔒 | Device | Immediate | RSA-2048 wrapped | 2 cloud calls |
| [`host_auth_ek.py`](host_auth_ek.py) | Device | Polled | plaintext over HTTPS | 3 cloud calls |
| [`host_auth_ek_rsa2048.py`](host_auth_ek_rsa2048.py) | Device | Polled | RSA-2048 wrapped | 3 cloud calls |
| [`token_auth_ek.py`](token_auth_ek.py) | Cloud | Polled | plaintext over HTTPS | 4 cloud calls |
| [`token_auth_ek_rsa2048.py`](token_auth_ek_rsa2048.py) | Cloud | Polled | RSA-2048 wrapped | 4 cloud calls |

⭐ **Start with `host_auth_ek_priority.py`.**
🔒 **Use the `_rsa2048` form when HTTPS alone is not enough** - a terminating proxy, a TLS-inspection middlebox, or a rule that forbids key material being readable at any hop. These require `pip install cryptography` and add a local RSA-2048 keygen (~0.1–1 s).

---

## How RSA-2048 EK delivery works

The `_rsa2048` scripts generate a fresh keypair per run, send the public half with the request, and receive the EK inside a **hybrid-crypto-js** envelope - an AES-CBC ciphertext plus the AES key wrapped with RSA-OAEP. Only the caller's private key opens it, so the EK is protected end to end rather than only in transit.

Note that the envelope format requires **SHA-1** in OAEP/MGF1, and the PKCS7 padding is stripped without validation. Both are interoperability constraints - see [known-issues](../../docs/known-issues.md).

---

## `host_auth_ek_priority.py` - Device-Initiated, Synchronous ⭐

```text
┌───────────┐              ┌──────────┐              ┌───────────────┐
│   Token   │              │  Script  │              │  CyberRock    │
│  (HMAC HW)│              │          │              │    Cloud      │
└─────┬─────┘              └────┬─────┘              └──────┬────────┘
      │◄── get_tid() ────────── │                           │
      │──── TID ───────────────►│── make_challenge() → HCW  │
      │◄── do_host_auth_ek(HCW) │                           │
      │──── HRW, EK_token ────► │── do_device_login() ─────►│
      │                         │── EKpriorityhostauth ────►│
      │                         │   (TID, HCW, HRW)         │
      │                         │◄── AUTH_OK, EK_cloud ──── │
      │                         │── compare EK match        │
      │                         │                           │
```

---

## `host_auth_ek_priority_rsa2048.py` - Device-Initiated, Synchronous, Encrypted 🔒

```text
┌───────────┐              ┌──────────┐              ┌───────────────┐
│   Token   │              │  Script  │              │  CyberRock    │
│  (HMAC HW)│              │          │              │    Cloud      │
└─────┬─────┘              └────┬─────┘              └──────┬────────┘
      │                         │── generate RSA-2048       │
      │◄── get_tid() ────────── │                           │
      │──── TID ───────────────►│── make_challenge() → HCW  │
      │◄── do_host_auth_ek(HCW) │                           │
      │──── HRW, EK_token ────► │── do_device_login() ─────►│
      │                         │── EKpriorityhostauth_rsa ►│
      │                         │   (TID,HCW,HRW,pubkey)    │
      │                         │◄── AUTH_OK, encrypted_EK  │
      │                         │── RSA decrypt → EK        │
      │                         │── compare EK match        │
      │                         │                           │
```

The strongest and quickest variant: one round-trip, key never readable in transit.

---

## `host_auth_ek.py` - Device-Initiated, Asynchronous

```text
┌───────────┐              ┌──────────┐              ┌───────────────┐
│   Token   │              │  Script  │              │  CyberRock    │
│  (HMAC HW)│              │          │              │    Cloud      │
└─────┬─────┘              └────┬─────┘              └──────┬────────┘
      │◄── get_tid() ────────── │                           │
      │──── TID ───────────────►│── make_challenge() → HCW  │
      │◄── do_host_auth_ek(HCW) │                           │
      │──── HRW, EK_token ────► │── do_device_login() ─────►│
      │                         │── hostauthEK_request ────►│
      │                         │   (TID, HCW, HRW)         │
      │                         │◄── transactionid ──────── │
      │                         │── hostauthEK_checkstatus ►│
      │                         │◄── AUTH_OK, EK_cloud ──── │
      │                         │── compare EK match        │
      │                         │                           │
```

---

## `host_auth_ek_rsa2048.py` - Device-Initiated, Asynchronous, Encrypted

```text
┌───────────┐              ┌──────────┐              ┌───────────────┐
│   Token   │              │  Script  │              │  CyberRock    │
│  (HMAC HW)│              │          │              │    Cloud      │
└─────┬─────┘              └────┬─────┘              └──────┬────────┘
      │                         │── generate RSA-2048       │
      │◄── get_tid() ────────── │                           │
      │──── TID ───────────────►│── make_challenge() → HCW  │
      │◄── do_host_auth_ek(HCW) │                           │
      │──── HRW, EK_token ────► │── do_device_login() ─────►│
      │                         │◄── accesstoken ────────── │
      │                         │── hostauthEK_request_rsa ►│
      │                         │   (TID,HCW,HRW,pubkey)    │
      │                         │◄── transactionid ──────── │
      │                         │── hostauthEK_checkstatus  │
      │                         │   _rsa ─────────────────► │
      │                         │◄── AUTH_OK, encrypted_EK  │
      │                         │── RSA decrypt → EK        │
      │                         │── compare EK match        │
      │                         │                           │
```

---

## `token_auth_ek.py` - Cloud-Initiated

```text
┌───────────┐              ┌──────────┐              ┌───────────────┐
│   Token   │              │  Script  │              │  CyberRock    │
│  (HMAC HW)│              │          │              │    Cloud      │
└─────┬─────┘              └────┬─────┘              └──────┬────────┘
      │◄── get_tid() ────────── │── do_device_login() ─────►│
      │──── TID ───────────────►│◄── accesstoken ────────── │
      │                         │── tokenauthEK_requestcw ─►│
      │                         │◄── CW, transactionid ──── │
      │◄── do_token_auth_ek(CW) │                           │
      │──── RW, EK_token ──────►│── tokenauthEK_replyrw ───►│
      │                         │── tokenauthEK_checkstatus►│
      │                         │◄── AUTH_OK, EK_cloud ──── │
      │                         │── compare EK_token ==     │ 
      │                         │   EK_cloud                │
      │                         │                           │
```

---

## `token_auth_ek_rsa2048.py` - Cloud-Initiated, Encrypted

```text
┌───────────┐              ┌──────────┐              ┌───────────────┐
│   Token   │              │  Script  │              │  CyberRock    │
│  (HMAC HW)│              │          │              │    Cloud      │
└─────┬─────┘              └────┬─────┘              └─────┬────────┘
      │                         │── generate RSA-2048      │
      │                         │   keypair (local)        │
      │◄── get_tid() ────────── │── do_device_login() ─────│
      │──── TID ───────────────►│◄── accesstoken ──────────│
      │                         │── tokenauthEK_requestcw  │
      │                         │   _rsa(pubkey) ──────────│
      │                         │◄── CW, transactionid ────│
      │◄── do_token_auth_ek(CW) │                          │
      │──── RW, EK_token ──────►│── tokenauthEK_replyrw ───│
      │                         │── tokenauthEK_checkstatus│
      │                         │   _rsa ─────────────────►│
      │                         │◄── AUTH_OK, encrypted_EK │
      │                         │── RSA decrypt → EK_cloud │
      │                         │── compare EK match       │
      │                         │                          │
```

⚠️ This file carries a preserved defect - a dead first decryption pass in `decrypt_hybrid_ek()`. Harmless (the result is discarded and recomputed correctly), but do not copy it forward. See [known-issues](../../docs/known-issues.md).

---

**Next:** [`../04-sign-and-verify-data/`](../04-sign-and-verify-data/) - tag your own data instead of a generated challenge.
[Back to all examples](../README.md) · [Configuration](../../docs/configuration.md) · [Known issues](../../docs/known-issues.md)
