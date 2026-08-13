# SandGrain CyberRock - Python SDK

Hardware-anchored trust for connected devices. A physical CyberRock token (SGT1001) acts as a hardware HMAC engine; the CyberRock Cloud holds the matching secret in an HSM-backed enclave. Every flow in this SDK is a variation on one idea:

> a challenge is issued, only the genuine token can compute the response, and the cloud verifies it independently.

Because the secret never leaves the hardware and is never transmitted, possession of the token is the credential - not a key file that can be copied off a disk.

---

## Start here

**→ [`examples/README.md`](examples/README.md)** - 27 self-contained examples organised by what you are trying to achieve, with a decision table for picking the right one.

Copy the closest example into your project and replace the block marked `YOUR INTEGRATION POINT`. Nothing else is required beyond the four core modules.

```bash
# 1. confirm the token responds (no credentials needed)
python examples/01-getting-started/token_id.py

# 2. your first full round-trip
python examples/02-prove-device-identity/host_auth_priority.py
```

Before either will work, set your credentials and interface: **[`docs/configuration.md`](docs/configuration.md)**.

---

## What the SDK can do

| Capability | Where |
| --- | --- |
| **Device identification** - read the token's unique TID | [`examples/01-getting-started/`](examples/01-getting-started/) |
| **Hardware self-test** - verify the token is healthy | [`examples/01-getting-started/`](examples/01-getting-started/) |
| **Token claiming** - bind a token to your tenant account | [`examples/01-getting-started/`](examples/01-getting-started/) |
| **Device authentication** - prove the device is genuine, cloud- or device-initiated | [`examples/02-prove-device-identity/`](examples/02-prove-device-identity/) |
| **Mutual authentication** - the cloud proves itself to the device as well | [`examples/02-prove-device-identity/`](examples/02-prove-device-identity/) |
| **Ephemeral Key derivation** - a session key both sides derive but never transmit | [`examples/03-derive-session-key/`](examples/03-derive-session-key/) |
| **RSA-2048 encrypted key delivery** - EK confidentiality beyond HTTPS | [`examples/03-derive-session-key/`](examples/03-derive-session-key/) |
| **HRW generation** - a hardware-backed tag over your own data | [`examples/04-sign-and-verify-data/`](examples/04-sign-and-verify-data/) |
| **Secure boot attestation** - prove which firmware actually ran | [`examples/05-attest-boot-chain/`](examples/05-attest-boot-chain/) |
| **Daisy chain** - cover a batch of items with a single verification | [`examples/06-chain-multiple-items/`](examples/06-chain-multiple-items/) |

---

## Repository layout

```text
.
├── examples/                    27 runnable demo scripts, grouped by outcome
│   ├── 01-getting-started/          3   Is the token alive, healthy, and mine?
│   ├── 02-prove-device-identity/    6   Is this device genuine?
│   ├── 03-derive-session-key/       6   Give me a shared key neither side transmits
│   ├── 04-sign-and-verify-data/     6   Tag my own data with the hardware
│   ├── 05-attest-boot-chain/        3   Prove which firmware actually ran
│   └── 06-chain-multiple-items/     3   Cover a batch with one verification
│
├── docs/                        Setup and caveats
├── scripts/                     Maintenance tooling (not needed to integrate)
├── tests/                       Unit tests for the shared token helpers
│
├── CyberRock_Token.py           Core module - hardware abstraction (SPI/USB)
├── CyberRock_Cloud.py           Core module - REST client, 48 endpoints
├── CyberRock_Config.py          Core module - interface + environment config
├── SandGrain_Credentials.py     Core module - credential store (edit in place)
├── README.md                    This file
└── system_diagram.md            Architecture and protocol overview
```

**Every folder has its own README.** Each `examples/NN-*/README.md` explains what those scripts are for, gives a table for choosing between the variants, and includes a sequence diagram for each script.

| Folder | Contents |
| --- | --- |
| [`examples/`](examples/) | The integration surface. Start at [`examples/README.md`](examples/README.md) for the decision table. |
| [`examples/01-getting-started/`](examples/01-getting-started/) | `token_id.py` · `bist.py` · `token_claim.py` - run these first; the first two need no credentials or network. |
| [`examples/02-prove-device-identity/`](examples/02-prove-device-identity/) | `token_auth.py` · `host_auth.py` · `host_auth_priority.py` · `host_auth_hrwrequest.py` · `mutual_auth.py` · `mutual_auth_host.py` |
| [`examples/03-derive-session-key/`](examples/03-derive-session-key/) | `token_auth_ek.py` · `token_auth_ek_rsa2048.py` · `host_auth_ek.py` · `host_auth_ek_priority.py` · `host_auth_ek_rsa2048.py` · `host_auth_ek_priority_rsa2048.py` |
| [`examples/04-sign-and-verify-data/`](examples/04-sign-and-verify-data/) | `hrwrequest.py` · `hrwrequest_priority.py` · `hrwrequest_ek.py` · `hrwrequest_ek_priority.py` · `hrwrequest_ek_rsa2048.py` · `hrwrequest_ek_priority_rsa2048.py` |
| [`examples/05-attest-boot-chain/`](examples/05-attest-boot-chain/) | `secureboot.py` · `secureboot_host.py` · `secureboot_hrw.py` |
| [`examples/06-chain-multiple-items/`](examples/06-chain-multiple-items/) | `daisychain.py` · `daisychain_host.py` · `daisychain_hrw.py` |
| [`docs/`](docs/) | [`configuration.md`](docs/configuration.md) - wiring, interface, credentials, dependencies. [`known-issues.md`](docs/known-issues.md) - preserved defects and production caveats. |
| [`scripts/`](scripts/) | `verify_migration.py` - AST harness used to prove the 2026-08 reorganisation changed no protocol behaviour. Kept for reference; not needed to use the SDK. |
| [`tests/`](tests/) | `test_token_helpers.py` - verifies `hex_to_bytes()` and `make_challenge()` match the idioms they replaced. Run with `python3 -m unittest discover tests`. |

---

## Core modules

The four files an integration vendors, alongside whichever example it started from:

| Module | Purpose |
| --- | --- |
| `CyberRock_Token.py` | Hardware abstraction (SPI and USB serial). Frame assembly/disassembly, token commands (IDENT, CR, CR_EK, HCR, HCR_EK, BIST), and the shared `hex_to_bytes()` / `make_challenge()` helpers. |
| `CyberRock_Cloud.py` | REST client for the CyberRock Cloud device API - 48 endpoint wrappers covering every flow above, plus tenant login and claiming. |
| `CyberRock_Config.py` | Platform detection, interface selection (SPI/USB), serial port, environment URL. Initialises `CyberRock_Token`. |
| `SandGrain_Credentials.py` | Credential store. **Template - edit in place, and see the warning in [`docs/configuration.md`](docs/configuration.md) before committing it.** |

---

## Requirements

Python 3.9+, `requests`, `pyserial`. The `_rsa2048` examples additionally need `cryptography`. SPI is Linux/Raspberry Pi only; USB works everywhere. Full setup in [`docs/configuration.md`](docs/configuration.md).

---

## Documentation

- [`examples/README.md`](examples/README.md) - example index, decision table, filename vocabulary
- **Each `examples/NN-*/README.md`** - what that folder's scripts are for, how to choose between them, and a sequence diagram per script
- [`docs/configuration.md`](docs/configuration.md) - wiring, interface, credentials, dependencies
- [`docs/known-issues.md`](docs/known-issues.md) - preserved defects and production caveats. **Read before copying** `examples/06-chain-multiple-items/daisychain_host.py` or `examples/05-attest-boot-chain/secureboot_hrw.py`.
- [`system_diagram.md`](system_diagram.md) - full architecture and protocol overview

---

## Support

SandGrain / IoT Integration Team - **<support@sandgrain.eu>**

Credentials are issued once SandGrain has created your Tenant user account.

## License

Proprietary, for use within the SandGrain suite ecosystem. Do not distribute or modify without authorization.
