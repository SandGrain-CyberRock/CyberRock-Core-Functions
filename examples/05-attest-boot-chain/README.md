# 05 - Attest a Boot Chain

**Prove which firmware actually ran, not just that the device is genuine.**

A device can be authentic and still be running tampered firmware. Secure boot attestation closes that gap: each boot stage's hash is folded into a running value that passes through the token at every level, producing one final attestation value. Change any stage - or reorder them - and the final value changes.

**The chain**, per level:

```text
CW(n)    = chain_value XOR FW_hash(n)      (per-nibble XOR)
RW(n)    = token.do_host_auth(CW(n))
chain    = RW(n) || RW(n)                  (doubled to 32 bytes for the next challenge)
```

The first level starts from a `BootCW` - supplied by the cloud, or generated locally, depending on the script.

| Script | BootCW from | Purpose | Cost |
| --- | --- | --- | --- |
| [`secureboot_host.py`](secureboot_host.py) ⭐ | Device | Attest at boot, before trusting the network | 3 cloud calls, 3 transfers |
| [`secureboot.py`](secureboot.py) | Cloud | Server-driven attestation | 4 cloud calls, 3 transfers |
| [`secureboot_hrw.py`](secureboot_hrw.py) | Device | Ask the cloud for the *expected* value | 3 cloud calls, 4 transfers |

⭐ **Start with `secureboot_host.py`** - attestation usually happens at boot, when the device has no reason to trust the network yet.

**Using real firmware:** the examples substitute SHA-256 of fixed strings. `secureboot_host.py` includes a `compute_file_hash()` helper - point it at your actual boot images.

---

## `secureboot_host.py` - Device-Initiated ⭐

The device picks its own `BootCW`, walks the chain locally, and submits the starting value plus the final attestation once online.

```text
┌───────────┐              ┌──────────┐              ┌───────────────┐
│   Token   │              │  Script  │              │  CyberRock    │
│  (HMAC HW)│              │          │              │    Cloud      │
└─────┬─────┘              └────┬─────┘              └──────┬────────┘
      │◄── get_tid() ──────────│                           │
      │──── TID ───────────────►│── compute FW hashes      │
      │                         │── make_challenge()→BootCW│
      │                         │   CW1 = BootCW XOR FW2   │
      │◄── do_host_auth(CW1) ──│                           │
      │──── RW1 ───────────────►│   chain = RW1||RW1       │
      │                         │   CW2 = chain XOR FW3    │
      │◄── do_host_auth(CW2) ──│                           │
      │──── attestation_value ─►│── do_device_login() ─────►│
      │                         │── requestHostSecureBoot ─►│
      │                         │   (TIDs, hashes,         │
      │                         │    BootCW, attestation)  │
      │                         │── checkHostSecureBoot ───►│
      │                         │◄── AUTH_OK ──────────────│
      │                         │                           │
```

A failure means the declared chain does not match what the cloud expects - halt the boot or quarantine the device.

---

## `secureboot.py` - Cloud-Initiated

The cloud supplies the starting challenge, so it controls when attestation happens and against which chain.

```text
┌───────────┐              ┌──────────┐              ┌───────────────┐
│   Token   │              │  Script  │              │  CyberRock    │
│  (HMAC HW)│              │          │              │    Cloud      │
└─────┬─────┘              └────┬─────┘              └──────┬────────┘
      │◄── get_tid() ──────────│                           │
      │──── TID ───────────────►│── compute FW hashes      │
      │                         │── do_device_login() ─────►│
      │                         │── requestSecureBootCW ───►│
      │                         │   (TIDs, FW hashes)      │
      │                         │◄── CW, transactionid ────│
      │                         │   CW1 = CW XOR FW2hash  │
      │◄── do_host_auth(CW1) ──│                           │
      │──── RW1 ───────────────►│   chain = RW1||RW1       │
      │                         │   CW2 = chain XOR FW3hash│
      │◄── do_host_auth(CW2) ──│                           │
      │──── attestation_value ─►│── replySecureBootRW ─────►│
      │                         │── checkSecureBootStatus ─►│
      │                         │◄── AUTH_OK ──────────────│
      │                         │                           │
```

---

## `secureboot_hrw.py` - Expected Value

Instead of submitting a value for a yes/no verdict, this asks the cloud to compute what the attestation *should* be for a given chain. Use it to record a known-good reference at provisioning time, or to find which stage of a failing chain diverged.

```text
┌───────────┐              ┌──────────┐              ┌───────────────┐
│   Token   │              │  Script  │              │  CyberRock    │
│  (HMAC HW)│              │          │              │    Cloud      │
└─────┬─────┘              └────┬─────┘              └──────┬────────┘
      │◄── get_tid() ────────── │                           │
      │──── TID ───────────────►│── FW2, FW3, FW4 hashes    │
      │                         │── make_challenge()→BootCW │
      │◄── do_host_auth(CW1) ── │   CW1 = BootCW XOR FW2    │
      │──── RW1 ───────────────►│   chain = RW1||RW1        │
      │◄── do_host_auth(CW2) ── │   CW2 = chain XOR FW3     │
      │──── RW2 ───────────────►│   chain = RW2||RW2        │
      │◄── do_host_auth(CW3) ── │   CW3 = chain XOR FW4     │
      │──── attestation_local ─►│── do_device_login() ─────►│
      │                         │── requestSecureBootHRW ──►│
      │                         │   (TIDs, hashes, BootCW)  │
      │                         │── checkSecureBootHRW ────►│
      │                         │◄── attestation_cloud ──── │
      │                         │── compare local == cloud  │
      │                         │                           │
```

Three levels here rather than two - chain length is yours to choose.

⚠️ This file carries a preserved defect: the three computed firmware hashes are overwritten by hardcoded constants, so it attests a fixed synthetic chain rather than the hashes it appears to compute. See [known-issues](../../docs/known-issues.md).

---

**Next:** [`../06-chain-multiple-items/`](../06-chain-multiple-items/) - the same chaining idea applied to arbitrary data batches.
[Back to all examples](../README.md) · [Configuration](../../docs/configuration.md) · [Known issues](../../docs/known-issues.md)
