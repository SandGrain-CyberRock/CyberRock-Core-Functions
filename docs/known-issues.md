# Known Issues

Four defects were identified during the 2026-08-10 restructure and initially preserved so the reorganised examples stayed byte-equivalent in behaviour to the versions already validated against hardware. The upstream repository has since fixed all four (`python-test-scripts-jeroen`, commit `a20a214`, 2026-08-21: "Fix bugs and clean up"), and those fixes are now applied here as well.

## Resolved

1. **Daisy-chain loop did not advance** (`examples/06-chain-multiple-items/daisychain_host.py`) - the loop read the pre-loop `hrw` on every pass instead of the previous pass's result. Fixed: the loop now advances a running `hrw_n`, and the example chains two data items across three TIDs.
2. **Generated challenge overwritten by a constant** (`examples/06-chain-multiple-items/daisychain_host.py`) - the `make_challenge()` result was discarded and replaced by a fixed, publicly known value. Fixed: the generated challenge is used.
3. **Computed firmware hashes overwritten by constants** (`examples/05-attest-boot-chain/secureboot_hrw.py`) - three `hashlib` digests were computed and immediately replaced by hardcoded values. Fixed: the dead computation is removed; the fixed test values are kept deliberately for reproducible attestation.
4. **Dead first decryption pass** (`examples/03-derive-session-key/token_auth_ek_rsa2048.py`) - `decrypt_hybrid_ek()` ran a no-op first pass whose result was discarded and recomputed. Fixed: single decryption pass.

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
