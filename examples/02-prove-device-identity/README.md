# 02 — Prove Device Identity

**Is this device genuine?**

The core question the SDK exists to answer. A challenge is issued, only the real token can compute the response, and the cloud verifies it against its HSM. Because the secret never leaves the hardware, this proves *possession of the token* — not knowledge of a key that could have been copied.

| Script | Challenge from | Result | Cost |
| --- | --- | --- | --- |
| [`host_auth_priority.py`](host_auth_priority.py) ⭐ | Device | Immediate | 2 cloud calls |
| [`host_auth.py`](host_auth.py) | Device | Polled | 3 cloud calls |
| [`token_auth.py`](token_auth.py) | Cloud | Polled | 4 cloud calls |
| [`host_auth_hrwrequest.py`](host_auth_hrwrequest.py) | Device | Polled + cross-check | 5 cloud calls |
| [`mutual_auth.py`](mutual_auth.py) | Cloud | Polled, **cloud proves itself too** | 4 cloud calls |
| [`mutual_auth_host.py`](mutual_auth_host.py) | Device | Polled, **cloud proves itself too** | 3 cloud calls |

⭐ **Start with `host_auth_priority.py`** — shortest complete round-trip, and the pattern most integrations build on.

**Choosing:**

- *Who decides when to check?* Device → `host_auth*`. Cloud → `token_auth`.
- *Can you wait?* No → `_priority`. Yes → the polling variant.
- *Do you trust the endpoint?* No → `mutual_auth*`, which also proves the cloud is genuine.

All flows also need the token to be **claimed** first — an unclaimed token returns `CLAIM_TOKEN`. See [`../01-getting-started/token_claim.py`](../01-getting-started/token_claim.py).

---

## `host_auth_priority.py` — Device-Initiated, Synchronous ⭐

The device generates its own challenge, has the token sign it, and submits both. The verdict comes back in the same call.

```text
┌───────────┐              ┌──────────┐              ┌───────────────┐
│   Token   │              │  Script  │              │  CyberRock    │
│  (HMAC HW)│              │          │              │    Cloud      │
└─────┬─────┘              └────┬─────┘              └──────┬────────┘
      │◄── get_tid() ──────────│                           │
      │──── TID ───────────────►│── make_challenge() → HCW │
      │◄── do_host_auth(HCW) ──│                           │
      │──── HRW ───────────────►│── do_device_login() ─────►│
      │                         │◄── accesstoken ──────────│
      │                         │── priorityhostauth ──────►│
      │                         │   (TID, HCW, HRW)        │
      │                         │◄── AUTH_OK (immediate) ──│
      │                         │                           │
```

No polling. One request, one answer.

---

## `host_auth.py` — Device-Initiated, Asynchronous

Identical proof, but submission and verdict are separate calls. Use when the device may go offline between the two, or when the caller should not block.

```text
┌───────────┐              ┌──────────┐              ┌───────────────┐
│   Token   │              │  Script  │              │  CyberRock    │
│  (HMAC HW)│              │          │              │    Cloud      │
└─────┬─────┘              └────┬─────┘              └──────┬────────┘
      │◄── get_tid() ──────────│                           │
      │──── TID ───────────────►│── make_challenge() → HCW │
      │                         │── do_device_login() ─────►│
      │                         │◄── accesstoken ──────────│
      │◄── do_host_auth(HCW) ──│                           │
      │──── HRW ───────────────►│── hostauth_request ──────►│
      │                         │   (TID, HCW, HRW)        │
      │                         │◄── transactionid ────────│
      │                         │── hostauth_checkstatus ──►│
      │                         │◄── AUTH_OK ──────────────│
      │                         │                           │
```

`checkstatus` polls until a terminal status. **It has no timeout** — see [known-issues](../../docs/known-issues.md).

---

## `token_auth.py` — Cloud-Initiated

The cloud supplies the challenge. Use when verification is driven server-side — a scheduled re-attestation, an admin-triggered check — rather than by the device.

```text
┌───────────┐              ┌──────────┐              ┌───────────────┐
│   Token   │              │  Script  │              │  CyberRock    │
│  (HMAC HW)│              │          │              │    Cloud      │
└─────┬─────┘              └────┬─────┘              └──────┬────────┘
      │◄── get_tid() ──────────│                           │
      │──── TID ───────────────►│── do_device_login() ─────►│
      │                         │◄── accesstoken ──────────│
      │                         │── tokenauth_requestcw ───►│
      │                         │◄── CW, transactionid ────│
      │◄── do_token_auth(CW) ──│                           │
      │──── RW ────────────────►│── tokenauth_replyrw ─────►│
      │                         │── tokenauth_checkstatus ─►│
      │                         │◄── AUTH_OK / CLAIM_TOKEN ─│
      │                         │                           │
```

Three steps rather than two: the challenge has to be fetched before the token can answer it.

---

## `host_auth_hrwrequest.py` — Device-Initiated + Cloud Cross-Check

Authenticates, then separately asks the cloud to derive the HRW for the *same* challenge. Useful during bring-up: comparing the two answers tells you whether a failure is in the token, the challenge handling, or the verification.

```text
┌───────────┐              ┌──────────┐              ┌───────────────┐
│   Token   │              │  Script  │              │  CyberRock    │
│  (HMAC HW)│              │          │              │    Cloud      │
└─────┬─────┘              └────┬─────┘              └──────┬────────┘
      │◄── get_tid() ──────────│                           │
      │──── TID ───────────────►│── make_challenge() → HCW │
      │                         │── do_device_login() ─────►│
      │                         │◄── accesstoken ──────────│
      │◄── do_host_auth(HCW) ──│                           │
      │──── HRW ───────────────►│── hostauth_request ──────►│
      │                         │── hostauth_checkstatus ──►│
      │                         │◄── AUTH_OK ──────────────│
      │                         │── requestHRW(TID, HCW) ──►│
      │                         │── requestHRWstatus ──────►│
      │                         │◄── HRW_cloud ────────────│
      │                         │── compare HRW == HRW_cloud│
      │                         │                           │
```

A diagnostic, not a production pattern — it doubles the cloud traffic for information you only need while integrating.

---

## `mutual_auth.py` — Mutual, Cloud-Initiated

Plain authentication proves the device to the cloud. This also proves the cloud to the device: after accepting the token's RW, the cloud returns `HRW2`, which the device can reproduce locally. Only a party holding the same secret can produce it, so an impostor server is caught.

```text
┌───────────┐              ┌──────────┐              ┌───────────────┐
│   Token   │              │  Script  │              │  CyberRock    │
│  (HMAC HW)│              │          │              │    Cloud      │
└─────┬─────┘              └────┬─────┘              └──────┬────────┘
      │◄── get_tid() ──────────│── do_device_login() ─────►│
      │──── TID ───────────────►│◄── accesstoken ──────────│
      │                         │── mutualauth_requestcw ──►│
      │                         │◄── CW, transactionid ────│
      │◄── do_token_auth(CW) ──│                           │
      │──── RW ────────────────►│── mutualauth_replyrw ────►│
      │                         │── mutualauth_checkstatus ►│
      │                         │◄── AUTH_OK, HRW2_cloud ──│
      │◄── do_host_auth(RW||RW)│                           │
      │──── HRW2_local ────────►│── compare HRW2 match     │
      │                         │                           │
```

**Both** conditions must hold. A good auth result with a mismatched `HRW2` means you are talking to an impostor — treat it as a failure.

---

## `mutual_auth_host.py` — Mutual, Device-Initiated

Same two-way guarantee, but the device supplies the challenge and drives the exchange. Here `HRW2` is derived from `HRW || HRW` rather than `RW || RW`.

```text
┌───────────┐              ┌──────────┐              ┌───────────────┐
│   Token   │              │  Script  │              │  CyberRock    │
│  (HMAC HW)│              │          │              │    Cloud      │
└─────┬─────┘              └────┬─────┘              └──────┬────────┘
      │◄── get_tid() ──────────│                           │
      │──── TID ───────────────►│── make_challenge() → HCW │
      │◄── do_host_auth(HCW) ──│                           │
      │──── HRW ───────────────►│── do_device_login() ─────►│
      │                         │── hostmutualauth_request ►│
      │                         │   (TID, HCW, HRW)        │
      │                         │── hostmutualauth_check ──►│
      │                         │◄── AUTH_OK, HRW2_cloud ──│
      │◄── do_host_auth(HRW||HRW)                         │
      │──── HRW2_local ────────►│── compare HRW2 match     │
      │                         │                           │
```

Preferred over `mutual_auth.py` when the device is the active party.

---

**Next:** [`../03-derive-session-key/`](../03-derive-session-key/) — same flows, but they also hand you a session key.
[Back to all examples](../README.md) · [Configuration](../../docs/configuration.md) · [Known issues](../../docs/known-issues.md)
