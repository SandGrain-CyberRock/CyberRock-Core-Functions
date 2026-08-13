# 06 - Chain Multiple Items

**Cover a whole batch with a single verification.**

When you have a set of values that must be proven together *and in order* - a batch of sensor readings, a sequence of log records, a manifest - chaining folds them into one value. One verification then replaces N, and altering, reordering or dropping any item changes the result.

**The chain:**

```text
HRW(0)   = token.do_host_auth(ChainCW)
HCW(n+1) = HRW(n) || data[n]              (32 hex + 32 hex = 64 hex)
HRW(n+1) = token.do_host_auth(HCW(n+1))
```

The token is invoked once for the initial challenge, then once per data item. The chain needs **one more TID than it has data items**.

Data items are 32-hex-character (16-byte) values. Hash anything larger down first.

| Script | ChainCW from | Purpose | Cost |
| --- | --- | --- | --- |
| [`daisychain.py`](daisychain.py) ⭐ | Cloud | Verify a batch, server-driven | 4 cloud calls, 4 transfers |
| [`daisychain_host.py`](daisychain_host.py) ⚠️ | Device | Verify a batch, device-driven | 3 cloud calls, 3 transfers |
| [`daisychain_hrw.py`](daisychain_hrw.py) | Device | Ask the cloud for the *expected* value | 3 cloud calls, 6 transfers |

⭐ **Start with `daisychain.py`** - it has a correct chain loop and is the clearest illustration of the pattern.

> ⚠️ **`daisychain_host.py` carries two preserved defects** - a hardcoded challenge that overrides the generated one, and a chain loop that does not advance. It is correct only because its `l_data` has exactly one item; **with two or more the submitted value is wrong**. Read [known-issues](../../docs/known-issues.md) before copying it, and take the loop from `daisychain.py` or `daisychain_hrw.py` instead.

---

## `daisychain.py` - Cloud-Initiated ⭐

```text
┌───────────┐              ┌──────────┐              ┌───────────────┐
│   Token   │              │  Script  │              │  CyberRock    │
│  (HMAC HW)│              │          │              │    Cloud      │
└─────┬─────┘              └────┬─────┘              └──────┬────────┘
      │◄── get_tid() ──────────│── do_device_login() ─────►│
      │──── TID ───────────────►│── requestDaisyChainCW ───►│
      │                         │   (TIDs, data_items)     │
      │                         │◄── CW, transactionid ────│
      │◄── do_host_auth(CW) ───│                           │
      │──── HRW1 ──────────────►│  HCW2 = HRW1 + data[0]  │
      │◄── do_host_auth(HCW2) ─│                           │
      │──── HRW2 ──────────────►│  HCW3 = HRW2 + data[1]  │
      │◄── do_host_auth(HCW3) ─│                           │
      │──── HRW3 (final) ──────►│── replyDaisyChainRW ─────►│
      │                         │── checkDaisyChainStatus ─►│
      │                         │◄── AUTH_OK ──────────────│
      │                         │                           │
```

Three TIDs, two data items. The loop reassigns the running `hrw` each pass - this is the correct pattern.

---

## `daisychain_host.py` - Device-Initiated ⚠️

Same idea, but the device supplies the `ChainCW`, so the chain can be built offline and submitted later.

```text
┌───────────┐              ┌──────────┐              ┌───────────────┐
│   Token   │              │  Script  │              │  CyberRock    │
│  (HMAC HW)│              │          │              │    Cloud      │
└─────┬─────┘              └────┬─────┘              └──────┬────────┘
      │◄── get_tid() ──────────│── ChainCW (hardcoded ⚠️) │
      │──── TID ───────────────►│── do_device_login() ─────►│
      │                         │◄── accesstoken ──────────│
      │◄── do_host_auth(HCW) ──│                           │
      │──── HRW ───────────────►│  HCW_n = HRW + data[0]  │
      │◄── do_host_auth(HCW_n) │                           │
      │──── HRW_n (final) ─────►│── HostDaisyChainAuth ────►│
      │                         │   (TIDs, data, HCW,      │
      │                         │    HRW_n)                │
      │                         │── checkHostDaisyChain ───►│
      │                         │◄── AUTH_OK ──────────────│
      │                         │                           │
```

Two TIDs, one data item - which is why the broken loop happens to produce the right answer here. See the warning above.

---

## `daisychain_hrw.py` - Expected Value

Instead of submitting a value for a yes/no verdict, this asks the cloud to derive the expected final `HRW` for a chain. Use it to record a known-good reference at provisioning time, or to locate which link of a failing chain diverged.

```text
┌───────────┐              ┌──────────┐              ┌───────────────┐
│   Token   │              │  Script  │              │  CyberRock    │
│  (HMAC HW)│              │          │              │    Cloud      │
└─────┬─────┘              └────┬─────┘              └──────┬────────┘
      │◄── get_tid() ──────────│── make_challenge()→ChainCW│
      │──── TID ───────────────►│                           │
      │◄── do_host_auth(       │                           │
      │      ChainCW) ─────────│                           │
      │──── HRW ───────────────►│  loop: HCW = HRW+data[n] │
      │◄── do_host_auth(HCW) ──│  (4 items, chain advances)│
      │──── HRW_local (final) ─►│── do_device_login() ─────►│
      │                         │── requestDaisyChainHRW ──►│
      │                         │   (TIDs, data, ChainCW)  │
      │                         │── checkDaisyChainHRW ────►│
      │                         │◄── HRW_cloud ────────────│
      │                         │── compare local == cloud │
      │                         │                           │
```

Five TIDs, four data items. No RW submission needed - the cloud derives its answer independently. This file also has a **correct** advancing loop worth copying.

---

**Back:** [all examples](../README.md) · [Configuration](../../docs/configuration.md) · [Known issues](../../docs/known-issues.md)
