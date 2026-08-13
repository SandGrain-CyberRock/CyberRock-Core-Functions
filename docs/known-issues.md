# Known Issues

Four defects were identified during the 2026-08-10 restructure. **All were deliberately left in place**: the restructure's rule was that presentation could change but protocol behaviour could not, so that the reorganised examples remain byte-equivalent in behaviour to the versions already validated against hardware.

They are recorded here so that anyone copying an example knows what they are inheriting. Each is also marked with an inline `NOTE:` comment at the site.

---

## 1. Daisy-chain loop does not advance

**File:** `examples/06-chain-multiple-items/daisychain_host.py`
**Was:** `CyberRockCoreFunctions/daisychain_host.py:58-61`

```python
for d in l_data:
    hcw_n = hrw + d          # reads `hrw` -- never reassigned
    hrw_n = token.do_host_auth(token.hex_to_bytes(hcw_n))
```

**Symptom.** The loop reads the pre-loop `hrw` on every pass instead of the value produced by the previous pass, so the chain never advances beyond its first link. Only the final iteration's result survives in `hrw_n`.

**Impact.** Latent today: `l_data` contains exactly one item, and with one item the loop is trivially correct. With **two or more items the submitted chain value is wrong** and the cloud will reject it. With an empty `l_data`, `hrw_n` is never bound and the script raises `NameError`.

**Correct pattern** - reassign the running value, as `examples/06-chain-multiple-items/daisychain_hrw.py` and `examples/06-chain-multiple-items/daisychain.py` both do:

```python
for d in l_data:
    hcw_next = hrw + d
    hrw = token.do_host_auth(token.hex_to_bytes(hcw_next))
```

---

## 2. Generated challenge overwritten by a constant

**File:** `examples/06-chain-multiple-items/daisychain_host.py`
**Was:** `CyberRockCoreFunctions/daisychain_host.py:46`

```python
hcw = token.make_challenge()
hcw = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
```

**Symptom.** The generated challenge is discarded on the next line, making the generation dead code.

**Impact.** The example always runs with a fixed, publicly known challenge. Fine for a demo against sandbox; **never do this in production** - a constant challenge makes the response replayable.

---

## 3. Computed firmware hashes overwritten by constants

**File:** `examples/05-attest-boot-chain/secureboot_hrw.py`
**Was:** `CyberRockCoreFunctions/secureboot_hrw.py:58-60`

Three `hashlib` digests are computed and then immediately replaced by hardcoded values, making the computation above them dead. Same pattern as issue 2. The example attests a fixed synthetic chain rather than the hashes it appears to compute.

---

## 4. Dead first decryption pass

**File:** `examples/03-derive-session-key/token_auth_ek_rsa2048.py`
**Was:** `CyberRockCoreFunctions/token_auth_ek_rsa2048.py:45-46`

```python
cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
padded = cipher.decryptor().update(cipher_text) + cipher.decryptor().finalize()
```

**Symptom.** `.update()` and `.finalize()` are called on two *different* decryptor objects. The result is discarded and recomputed correctly on the following lines.

**Impact.** None - provably a no-op. It is wasted work and a misleading read. The sibling `_rsa2048` examples do not have it; only this one was missed when the pattern was cleaned up.

---

## Notes for production integrators

These are not defects in the examples - they are properties of the SDK that you inherit by copying from it. Worth a decision before you ship.

### Challenge generation has one-second granularity

`CyberRock_Token.make_challenge()` hashes a timestamp formatted down to whole seconds:

```python
curr_time = _time.strftime("%a %d %b %Y %H %M %S", _time.gmtime(curr))
```

**Two calls within the same second return the same challenge.** Harmless in the single-shot examples here, but if you call it in a loop or across concurrent workers you will reuse challenges, and a reused challenge makes the response replayable. Use `secrets.token_hex(32)` or a monotonic counter in production.

### No request timeouts, and unbounded polling

`CyberRock_Cloud.py` sets **no `timeout=`** on any of its 48 endpoint wrappers, and its 17 status-polling loops have the shape:

```python
while status in ('NOT_READY', 'PROCESSING'):
    time.sleep(0.3)
    ...
```

with no attempt cap or deadline. A stalled network or a transaction that never reaches a terminal state **hangs the calling script indefinitely**. If you embed these flows in a service, wrap them with your own timeout, or add `timeout=` and a deadline to the client.

The synchronous (`_priority`) variants are less exposed here - they make one call rather than polling - but still have no request timeout.

### RSA path uses SHA-1 and unvalidated padding

In the `_rsa2048` examples, `decrypt_hybrid_ek()`:

- uses **SHA-1** in OAEP and MGF1 - required for hybrid-crypto-js wire compatibility, not a free choice;
- strips PKCS7 padding with `padded[:-padded[-1]]`, **without validating** it. Malformed input yields silent garbage rather than an error.

Both are interoperability constraints of the envelope format rather than bugs, but they should be understood before this code is relied on in a regulated context.
