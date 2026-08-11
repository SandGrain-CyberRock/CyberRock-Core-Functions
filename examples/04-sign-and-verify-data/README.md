# 04 — Sign and Verify Data

**Produce a tag over my own data that only this token could have made.**

The same challenge-response machinery, pointed at *your* data instead of a generated nonce. Put a 32-byte value in as the challenge (`HCW`) and the resulting `HRW` is a hardware-backed MAC over it: a firmware digest, a message hash, a serial number, a sensor reading.

The cloud can derive the same tag from `(TID, HCW)` without ever touching the token — so a verifier elsewhere in your system can check the tag without holding the hardware.

> **Substituting your own data:** every script here calls `token.make_challenge()` to produce a demo value. Replace that with your own 64-hex-character string. Anything longer must be hashed down to 32 bytes first.

| Script | Result | Also returns EK | EK delivery | Cost |
| --- | --- | --- | --- | --- |
| [`hrwrequest_priority.py`](hrwrequest_priority.py) ⭐ | Immediate | — | — | 2 cloud calls |
| [`hrwrequest.py`](hrwrequest.py) | Polled | — | — | 3 cloud calls |
| [`hrwrequest_ek_priority.py`](hrwrequest_ek_priority.py) | Immediate | yes | plaintext over HTTPS | 2 cloud calls |
| [`hrwrequest_ek.py`](hrwrequest_ek.py) | Polled | yes | plaintext over HTTPS | 3 cloud calls |
| [`hrwrequest_ek_priority_rsa2048.py`](hrwrequest_ek_priority_rsa2048.py) 🔒 | Immediate | yes | RSA-2048 wrapped | 2 cloud calls |
| [`hrwrequest_ek_rsa2048.py`](hrwrequest_ek_rsa2048.py) | Polled | yes | RSA-2048 wrapped | 3 cloud calls |

⭐ **Start with `hrwrequest_priority.py`** if you only need the tag.
Reach for an `_ek` variant when the same exchange should also establish a session key — it saves a round-trip versus doing folder 03 separately. 🔒 `_rsa2048` requires `pip install cryptography`.

---

## `hrwrequest_priority.py` — Tag Data, Immediate ⭐

```text
┌───────────┐              ┌──────────┐              ┌───────────────┐
│   Token   │              │  Script  │              │  CyberRock    │
│  (HMAC HW)│              │          │              │    Cloud      │
└─────┬─────┘              └────┬─────┘              └──────┬────────┘
      │◄── get_tid() ──────────│                           │
      │──── TID ───────────────►│── your data → HCW        │
      │◄── do_host_auth(HCW) ──│                           │
      │──── HRW_token ─────────►│── do_device_login() ─────►│
      │                         │── priorityrequestHRW ────►│
      │                         │   (TID, HCW)             │
      │                         │◄── HRW_cloud (immediate) │
      │                         │── compare HRW match      │
      │                         │                           │
```

Store `HRW_token` alongside your data as its hardware-anchored signature.

---

## `hrwrequest.py` — Tag Data, Polled

```text
┌───────────┐              ┌──────────┐              ┌───────────────┐
│   Token   │              │  Script  │              │  CyberRock    │
│  (HMAC HW)│              │          │              │    Cloud      │
└─────┬─────┘              └────┬─────┘              └──────┬────────┘
      │◄── get_tid() ──────────│                           │
      │──── TID ───────────────►│── your data → HCW        │
      │◄── do_host_auth(HCW) ──│                           │
      │──── HRW_token ─────────►│── do_device_login() ─────►│
      │                         │◄── accesstoken ──────────│
      │                         │── requestHRW(TID,HCW) ──►│
      │                         │── requestHRWstatus ──────►│
      │                         │◄── HRW_cloud ────────────│
      │                         │── compare HRW match      │
      │                         │                           │
```

---

## `hrwrequest_ek_priority.py` — Tag + Session Key, Immediate

```text
┌───────────┐              ┌──────────┐              ┌───────────────┐
│   Token   │              │  Script  │              │  CyberRock    │
│  (HMAC HW)│              │          │              │    Cloud      │
└─────┬─────┘              └────┬─────┘              └──────┬────────┘
      │◄── get_tid() ──────────│                           │
      │──── TID ───────────────►│── your data → HCW        │
      │◄── do_host_auth_ek(HCW)│                           │
      │──── HRW_token, EK_token►│── do_device_login() ─────►│
      │                         │── EKpriorityrequestHRW ──►│
      │                         │   (TID, HCW)             │
      │                         │◄── HRW_cloud, EK_cloud   │
      │                         │── compare HRW + EK match │
      │                         │                           │
```

Both values must match before you trust either.

---

## `hrwrequest_ek.py` — Tag + Session Key, Polled

```text
┌───────────┐              ┌──────────┐              ┌───────────────┐
│   Token   │              │  Script  │              │  CyberRock    │
│  (HMAC HW)│              │          │              │    Cloud      │
└─────┬─────┘              └────┬─────┘              └──────┬────────┘
      │◄── get_tid() ──────────│                           │
      │──── TID ───────────────►│── your data → HCW        │
      │◄── do_host_auth_ek(HCW)│                           │
      │──── HRW_token, EK_token►│── do_device_login() ─────►│
      │                         │◄── accesstoken ──────────│
      │                         │── EKrequestHRW(TID,HCW) ►│
      │                         │── EKrequestHRWstatus ────►│
      │                         │◄── HRW_cloud, EK_cloud ──│
      │                         │── compare HRW + EK match │
      │                         │                           │
```

---

## `hrwrequest_ek_priority_rsa2048.py` — Tag + Encrypted Key, Immediate 🔒

```text
┌───────────┐              ┌──────────┐              ┌───────────────┐
│   Token   │              │  Script  │              │  CyberRock    │
│  (HMAC HW)│              │          │              │    Cloud      │
└─────┬─────┘              └────┬─────┘              └──────┬────────┘
      │                         │── generate RSA-2048      │
      │◄── get_tid() ──────────│                           │
      │──── TID ───────────────►│── your data → HCW        │
      │◄── do_host_auth_ek(HCW)│                           │
      │──── HRW_token, EK_token►│── do_device_login() ─────►│
      │                         │── EKpriorityrequestHRW   │
      │                         │   _rsa(TID,HCW,pubkey) ─►│
      │                         │◄── HRW_cloud, encrypted_EK│
      │                         │── RSA decrypt → EK       │
      │                         │── compare HRW + EK match │
      │                         │                           │
```

---

## `hrwrequest_ek_rsa2048.py` — Tag + Encrypted Key, Polled

```text
┌───────────┐              ┌──────────┐              ┌───────────────┐
│   Token   │              │  Script  │              │  CyberRock    │
│  (HMAC HW)│              │          │              │    Cloud      │
└─────┬─────┘              └────┬─────┘              └──────┬────────┘
      │                         │── generate RSA-2048      │
      │◄── get_tid() ──────────│                           │
      │──── TID ───────────────►│── your data → HCW        │
      │◄── do_host_auth_ek(HCW)│                           │
      │──── HRW_token, EK_token►│── do_device_login() ─────►│
      │                         │◄── accesstoken ──────────│
      │                         │── EKrequestHRW_rsa ──────►│
      │                         │   (TID, HCW, pubkey)     │
      │                         │── EKrequestHRWstatus_rsa ►│
      │                         │◄── HRW_cloud, encrypted_EK│
      │                         │── RSA decrypt → EK       │
      │                         │── compare HRW + EK match │
      │                         │                           │
```

---

**Next:** [`../05-attest-boot-chain/`](../05-attest-boot-chain/) — chain several tags together to cover a boot sequence.
[Back to all examples](../README.md) · [Configuration](../../docs/configuration.md) · [Known issues](../../docs/known-issues.md)
