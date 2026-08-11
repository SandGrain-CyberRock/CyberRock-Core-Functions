# 01 — Getting Started

**Is the token alive, healthy, and mine?**

Run these three in order on a new setup. The first two need no credentials and no network, so they isolate hardware problems before cloud problems can confuse the picture.

| Script | Use it to | Needs | Cost |
| --- | --- | --- | --- |
| [`token_id.py`](token_id.py) | Read the token's unique identity (TID) | Token only | 1 token transfer |
| [`bist.py`](bist.py) | Run the hardware self-test | Token only | 2 transfers (4 with `--full`) |
| [`token_claim.py`](token_claim.py) | Bind the token to your tenant account | Token + IoT creds + **tenant creds** | up to 9 cloud calls |

**Start with `token_id.py`.** If it prints a 64-character TID, your wiring and interface config are correct.

---

## `token_id.py` — Token Identification

Reads the 32-byte TID that identifies this token. Every other flow begins by reading it, and every cloud call is scoped to it.

```text
┌───────────┐              ┌──────────┐              ┌───────────────┐
│   Token   │              │  Script  │              │  CyberRock    │
│  (HMAC HW)│              │          │              │    Cloud      │
└─────┬─────┘              └────┬─────┘              └──────┬────────┘
      │                         │                           │
      │◄── get_tid() ──────────│                           │
      │──── TID ───────────────►│                           │
      │                         │── print(TID)             │
      │                         │                           │
```

No cloud interaction.

---

## `bist.py` — Built-In Self-Test

Runs the token's own self-test. With `--full`, it also re-derives the TID, RW and EK through the normal command path and checks them against what BIST reported — so a disagreement points at the hardware rather than at your integration.

```text
┌───────────┐              ┌──────────┐              ┌───────────────┐
│   Token   │              │  Script  │              │  CyberRock    │
│  (HMAC HW)│              │          │              │    Cloud      │
└─────┬─────┘              └────┬─────┘              └──────┬────────┘
      │                         │                           │
      │◄── get_tid() ──────────│                           │
      │──── TID ───────────────►│                           │
      │◄── do_bist() ──────────│                           │
      │──── pass, PCC, ID,     │                           │
      │     RW, EK ────────────►│── check TID == PCC||ID   │
      │◄── do_token_auth(TID) ─│                           │
      │──── RW_verify ─────────►│── check RW match         │
      │◄── do_host_auth_ek(    │                           │
      │    ~TID) ──────────────│                           │
      │──── HRW, EK_verify ───►│── check EK match         │
      │                         │── print results          │
      │                         │                           │
```

No cloud interaction — all verification is local. Exits non-zero on failure, so you can gate a provisioning step on it.

```bash
python examples/01-getting-started/bist.py          # basic pass/fail
python examples/01-getting-started/bist.py --full   # + TID/RW/EK consistency
```

---

## `token_claim.py` — Token Claiming

A token straight from the factory is genuine but unowned: authenticating it returns `CLAIM_TOKEN` rather than `AUTH_OK`. Claiming binds it to your tenant. Run once per token.

```text
┌───────────┐              ┌──────────┐              ┌───────────────┐
│   Token   │              │  Script  │              │  CyberRock    │
│  (HMAC HW)│              │          │              │    Cloud      │
└─────┬─────┘              └────┬─────┘              └──────┬────────┘
      │◄── get_tid() ──────────│── do_device_login() ─────►│
      │──── TID ───────────────►│◄── accesstoken ──────────│
      │                         │                           │
      │  [Token Auth 3-step]    │── requestcw → replyrw ──►│
      │◄── do_token_auth(CW) ──│── checkstatus ───────────►│
      │──── RW ────────────────►│◄── CLAIM_TOKEN, claimid ─│
      │                         │                           │
      │                         │── do_tenant_login() ─────►│
      │                         │◄── tenant accesstoken ───│
      │                         │── do_tenant_claimtoken ──►│
      │                         │◄── claim OK ─────────────│
      │                         │                           │
      │  [Token Auth verify]    │── requestcw → replyrw ──►│
      │◄── do_token_auth(CW) ──│── checkstatus ───────────►│
      │──── RW ────────────────►│◄── AUTH_OK ──────────────│
      │                         │                           │
```

Authenticates, claims via the tenant API, then re-authenticates to confirm the claim took effect. This is the only script that needs `tenantusername` / `tenantpassword`.

If the first authentication already returns `AUTH_OK`, the token is claimed and the script exits early.

---

**Next:** [`../02-prove-device-identity/`](../02-prove-device-identity/) — prove the device is genuine.
[Back to all examples](../README.md) · [Configuration](../../docs/configuration.md)
