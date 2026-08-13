# SandGrain CyberRock Python SDK - System Diagram

## 1. Architecture Overview

```text
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              HOST SYSTEM                                         │
│                    (Raspberry Pi / Windows PC / Linux)                           │
│                                                                                 │
│  ┌───────────────────────────────────────────────────────────────────────────┐  │
│  │                         EXAMPLES (examples/)                               │  │
│  │                    (27 standalone demo scripts)                            │  │
│  │                                                                           │  │
│  │  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐    │  │
│  │  │ 01-getting-  │ │ 02-prove-    │ │ 03-derive-   │ │ 04-sign-and- │    │  │
│  │  │    started   │ │ device-      │ │ session-key  │ │ verify-data  │    │  │
│  │  │              │ │ identity     │ │              │ │              │    │  │
│  │  └──────┬───────┘ └──────┬───────┘ └──────┬───────┘ └──────┬───────┘    │  │
│  │  ┌──────┴───────┐ ┌──────┴───────┐ ┌──────┴───────┐ ┌──────┴───────┐    │  │
│  │  │ 05-attest-   │ │ 06-chain-    │ │  _ek /       │ │  _rsa2048 /  │    │  │
│  │  │ boot-chain   │ │ multiple-    │ │  _priority   │ │  _host/_hrw  │    │  │
│  │  │              │ │ items        │ │  variants    │ │  variants    │    │  │
│  │  └──────┬───────┘ └──────┬───────┘ └──────┬───────┘ └──────┬───────┘    │  │
│  │         │                 │                 │                 │           │  │
│  └─────────┼─────────────────┼─────────────────┼─────────────────┼───────────┘  │
│            │                 │                 │                 │               │
│            ▼                 ▼                 ▼                 ▼               │
│  ┌─────────────────────────────────────────────────────────────────────────┐    │
│  │                         CORE MODULES                                     │    │
│  │                                                                          │    │
│  │  ┌─────────────────┐  ┌─────────────────┐  ┌──────────────────────┐    │    │
│  │  │ CyberRock_Config│  │ CyberRock_Token │  │  CyberRock_Cloud     │    │    │
│  │  │                 │  │                 │  │                      │    │    │
│  │  │ • Platform det. │  │ • SPI transport │  │ • REST API client    │    │    │
│  │  │ • Interface sel.│  │ • USB transport │  │ • 48 endpoints       │    │    │
│  │  │ • Environment   │  │ • Frame asm/dis │  │ • Async polling      │    │    │
│  │  │ • Serial port   │  │ • HMAC API      │  │ • Auth headers       │    │    │
│  │  │                 │  │                 │  │ • _rsa variants      │    │    │
│  │  └────────┬────────┘  └───────┬─────────┘  └──────────┬───────────┘    │    │
│  │           │                   │                        │                │    │
│  │  ┌────────┴──────────────────────────────────────────────────────────┐  │    │
│  │  │                  SandGrain_Credentials                             │  │    │
│  │  │  • Cloudflare tokens  • IoT credentials  • Tenant credentials     │  │    │
│  │  └───────────────────────────────────────────────────────────────────┘  │    │
│  └─────────────────────────────────────────────────────────────────────────┘    │
│                                                                                 │
└────────────────┬──────────────────────────────────────────┬─────────────────────┘
                 │                                          │
                 │ SPI / USB Serial                         │ HTTPS
                 │                                          │
                 ▼                                          ▼
┌────────────────────────────┐              ┌──────────────────────────────────────┐
│     CYBERROCK TOKEN        │              │         CYBERROCK CLOUD              │
│     (Hardware HMAC)        │              │                                      │
│                            │              │  ┌────────────────────────────────┐  │
│  ┌──────────────────────┐  │              │  │     Cloudflare Access          │  │
│  │   SGT1001 / SGB      │  │              │  │   (CF-Access-Client-Id/Secret) │  │
│  │                      │  │              │  └───────────────┬────────────────┘  │
│  │  Commands:           │  │              │                  │                   │
│  │  • IDENT  (0x01)     │  │              │  ┌───────────────▼────────────────┐  │
│  │  • BIST   (0xFF)     │  │              │  │        Device API              │  │
│  │  • CR     (0x03)     │  │              │  │                                │  │
│  │  • CR_EK  (0x07)     │  │              │  │  • /api/auth/deviceLogin       │  │
│  │  • HCR    (0x05)     │  │              │  │  • /api/device/requestCW       │  │
│  │  • HCR_EK (0x06)     │  │              │  │  • /api/device/replyRW         │  │
│  │                      │  │              │  │  • /api/device/checkAuthStatus  │  │
│  │  Outputs:            │  │              │  │  • /api/device/priorityHostAuth │  │
│  │  • TID (32 bytes)    │  │              │  │  • /api/device/requestHRW       │  │
│  │  • RW  (16 bytes)    │  │              │  │  • /api/device/EKrequestCW      │  │
│  │  • HRW (16 bytes)    │  │              │  │  • /api/device/EKpriorityHost.. │  │
│  │  • EK  (16 bytes)    │  │              │  │  • ... (48 endpoints)           │  │
│  └──────────────────────┘  │              │  └───────────────┬────────────────┘  │
│                            │              │                  │                   │
│  Interface:                │              │  ┌───────────────▼────────────────┐  │
│  • SPI (10MHz, CS pin 22) │              │  │       HSM / CyberRock          │  │
│  • USB (115200 baud)      │              │  │         Enclave                 │  │
│                            │              │  │                                │  │
│  Frame: [CMD 4B][PCC 16B] │              │  │  • HMAC verification            │  │
│         [ID 16B][CW 32B]  │              │  │  • CW generation               │  │
│         [RW 16B][EK 16B]  │              │  │  • RW/HRW validation           │  │
└────────────────────────────┘              │  │  • EK derivation               │  │
                                            │  │  • EK RSA-2048 encryption      │  │
                                            │  │  • Token claiming              │  │
                                            │  └────────────────────────────────┘  │
                                            │                                      │
                                            │  Tenant API:                         │
                                            │  • tenantUserLogin, claim-token      │
                                            │                                      │
                                            │  Environments:                       │
                                            │  • SBX:  device-api.sandbox.sandgr.. │
                                            │  • PROD: device-api.cyberrock.sand.. │
                                            └──────────────────────────────────────┘
```

---

## 2. Key Protocol Flows

### 2.1 Token Authentication (3-Step)

```text
┌───────────┐              ┌──────────┐              ┌───────────────┐
│   Token   │              │   Host   │              │  CyberRock    │
│  (HMAC HW)│              │  Script  │              │    Cloud      │
└─────┬─────┘              └────┬─────┘              └──────┬────────┘
      │◄── get_tid() ──────────│── login() ────────────────►│
      │──── TID ───────────────►│◄── accessToken ───────────│
      │                         │── requestCW(TID) ─────────►│
      │                         │◄── CW, txId ─────────────│
      │◄── do_token_auth(CW) ──│                           │
      │──── RW ────────────────►│── replyRW(TID,CW,RW) ───►│
      │                         │── checkStatus(txId) ─────►│
      │                         │◄── AUTH_OK ──────────────│
```

### 2.2 Host Authentication (Priority)

```text
┌───────────┐              ┌──────────┐              ┌───────────────┐
│   Token   │              │   Host   │              │  CyberRock    │
│  (HMAC HW)│              │  Script  │              │    Cloud      │
└─────┬─────┘              └────┬─────┘              └──────┬────────┘
      │                         │── create HCW locally     │
      │◄── get_tid() ──────────│                           │
      │──── TID ───────────────►│                           │
      │◄── do_host_auth(HCW) ──│                           │
      │──── HRW ───────────────►│                           │
      │                         │── login() ───────────────►│
      │                         │◄── accessToken ──────────│
      │                         │── priorityHostAuth ──────►│
      │                         │   (TID, HCW, HRW)        │
      │                         │◄── AUTH_OK (immediate) ──│
```

### 2.3 EK Authentication with RSA-2048

```text
┌───────────┐              ┌──────────┐              ┌───────────────┐
│   Token   │              │   Host   │              │  CyberRock    │
│  (HMAC HW)│              │  Script  │              │    Cloud      │
└─────┬─────┘              └────┬─────┘              └──────┬────────┘
      │                         │── generate RSA keypair    │
      │◄── get_tid() ──────────│── login() ───────────────►│
      │──── TID ───────────────►│── EKrequestCW_rsa ──────►│
      │                         │   (TID, pubKey)          │
      │                         │◄── CW, txId ────────────│
      │◄── do_token_auth_ek(CW)│                           │
      │──── RW + EK_token ─────►│── EKreplyRW ────────────►│
      │                         │── EKcheckStatus_rsa ────►│
      │                         │◄── AUTH_OK + encrypted_EK│
      │                         │── decrypt → EK_cloud     │
      │                         │── verify EK match        │
```

### 2.4 Daisy Chain

```text
┌───────────┐              ┌──────────┐              ┌───────────────┐
│   Token   │              │   Host   │              │  CyberRock    │
│  (HMAC HW)│              │  Script  │              │    Cloud      │
└─────┬─────┘              └────┬─────┘              └──────┬────────┘
      │                         │── requestDaisyChainCW ───►│
      │                         │◄── CW, txId ────────────│
      │◄── do_host_auth(CW) ──│                           │
      │──── HRW1 ─────────────►│  HCW2 = HRW1 + data[0]  │
      │◄── do_host_auth(HCW2) │                           │
      │──── HRW2 ─────────────►│  HCW3 = HRW2 + data[1]  │
      │◄── do_host_auth(HCW3) │                           │
      │──── HRW3 ─────────────►│── replyDaisyChainRW ────►│
      │                         │── checkStatus ───────────►│
      │                         │◄── AUTH_OK ──────────────│
```

### 2.5 Secure Boot Attestation

```text
┌───────────┐              ┌──────────┐              ┌───────────────┐
│   Token   │              │   Host   │              │  CyberRock    │
│  (HMAC HW)│              │  Script  │              │    Cloud      │
└─────┬─────┘              └────┬─────┘              └──────┬────────┘
      │                         │── requestSecureBootCW ───►│
      │                         │   (TIDs[], FWhashes[])   │
      │                         │◄── BootCW, txId ─────────│
      │                         │  CW1 = BootCW XOR FW2   │
      │◄── do_host_auth(CW1) ──│                           │
      │──── RW1 ───────────────►│  chain = RW1||RW1        │
      │                         │  CW2 = chain XOR FW3    │
      │◄── do_host_auth(CW2) ──│                           │
      │──── attestation ───────►│── replySecureBootRW ────►│
      │                         │   (TIDs[], hashes[],     │
      │                         │    BootCW, attestation)  │
      │                         │── checkStatus ───────────►│
      │                         │◄── AUTH_OK ──────────────│
```

The token is never challenged with the raw BootCW: each level XORs the running
value with the next firmware hash first. One token call per boot stage.

---

## 3. Platform Support

| Feature | Linux / RPi | Windows |
| --------- | ------------- | --------- |
| SPI interface | Yes | No |
| USB interface | Yes | Yes |
| Cloud API | Yes | Yes |
| All auth flows | Yes | Yes |
| EK + RSA-2048 | Yes | Yes |
| Daisy Chain | Yes | Yes |
| Secure Boot | Yes | Yes |
| Mutual Auth | Yes | Yes |
| Token Claiming | Yes | Yes |
| Default serial port | /dev/ttyACM0 | COM3 |
| SPI → USB fallback | N/A | Automatic |
| Python required | 3.9+ | 3.9+ |

---

## 4. Project Directory Structure

```text
├── CyberRock_Token.py              # Hardware abstraction (SPI/USB) + shared helpers
├── CyberRock_Cloud.py              # REST API client (48 endpoints)
├── CyberRock_Config.py             # Interface + environment configuration
├── SandGrain_Credentials.py        # Credential store (template)
├── system_diagram.md               # This file
│
├── docs/
│   ├── configuration.md            # Wiring, interface, credentials, dependencies
│   └── known-issues.md             # Preserved defects + production caveats
│
├── scripts/
│   └── verify_migration.py         # Call-sequence equivalence harness
│
├── tests/
│   └── test_token_helpers.py       # Unit tests for the shared helpers
│
└── examples/                       # Standalone demo scripts (27 scripts)
    ├── README.md                           # Decision table + variant vocabulary
    │                                       # (each folder below also has a README
    │                                       #  with use cases + sequence diagrams)
    │
    ├── 01-getting-started/
    │   ├── token_id.py                     # Identification
    │   ├── bist.py                         # Built-In Self-Test
    │   └── token_claim.py                  # Token claiming
    │
    ├── 02-prove-device-identity/
    │   ├── token_auth.py                   # Token authentication
    │   ├── host_auth.py                    # Host authentication (async)
    │   ├── host_auth_priority.py           # Host auth (synchronous)
    │   ├── host_auth_hrwrequest.py         # Host auth + HRW request
    │   ├── mutual_auth.py                  # Mutual auth (cloud-initiated)
    │   └── mutual_auth_host.py             # Mutual auth (host-initiated)
    │
    ├── 03-derive-session-key/
    │   ├── token_auth_ek.py                # Token auth + Ephemeral Key
    │   ├── token_auth_ek_rsa2048.py        # Token auth + EK (RSA-2048)
    │   ├── host_auth_ek.py                 # Host auth + EK (async)
    │   ├── host_auth_ek_rsa2048.py         # Host auth + EK (async, RSA-2048)
    │   ├── host_auth_ek_priority.py        # Host auth + EK (synchronous)
    │   └── host_auth_ek_priority_rsa2048.py    # Host auth + EK (sync, RSA-2048)
    │
    ├── 04-sign-and-verify-data/
    │   ├── hrwrequest.py                   # HRW request (async)
    │   ├── hrwrequest_priority.py          # HRW request (synchronous)
    │   ├── hrwrequest_ek.py                # EK HRW request (async)
    │   ├── hrwrequest_ek_priority.py       # EK HRW request (synchronous)
    │   ├── hrwrequest_ek_rsa2048.py        # EK HRW request (async, RSA-2048)
    │   └── hrwrequest_ek_priority_rsa2048.py   # EK HRW request (sync, RSA-2048)
    │
    ├── 05-attest-boot-chain/
    │   ├── secureboot.py                   # Secure boot (cloud-initiated)
    │   ├── secureboot_host.py              # Secure boot (host-initiated)
    │   └── secureboot_hrw.py               # Secure boot HRW generation
    │
    └── 06-chain-multiple-items/
        ├── daisychain.py                   # Daisy chain (cloud-initiated)
        ├── daisychain_host.py              # Daisy chain (host-initiated)
        └── daisychain_hrw.py               # Daisy chain HRW generation
```

---

## 5. Detailed Flow Diagrams

Per-script sequence diagrams live alongside the code, in each folder's README:

- [`examples/01-getting-started/README.md`](examples/01-getting-started/README.md) - 3 scripts
- [`examples/02-prove-device-identity/README.md`](examples/02-prove-device-identity/README.md) - 6 scripts
- [`examples/03-derive-session-key/README.md`](examples/03-derive-session-key/README.md) - 6 scripts
- [`examples/04-sign-and-verify-data/README.md`](examples/04-sign-and-verify-data/README.md) - 6 scripts
- [`examples/05-attest-boot-chain/README.md`](examples/05-attest-boot-chain/README.md) - 3 scripts
- [`examples/06-chain-multiple-items/README.md`](examples/06-chain-multiple-items/README.md) - 3 scripts
