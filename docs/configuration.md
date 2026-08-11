# Configuration

Everything you need to set up before running an example. Three things must be right: the **credentials**, the **interface**, and the **environment**.

---

## 1. Credentials

All cloud flows read from `SandGrain_Credentials.py` at the repository root:

```python
cloudflaretokens = {
    'CF-Access-Client-Id': 'your_id.access',
    'CF-Access-Client-Secret': 'your_secret'
}

iotusername = 'your_device_username'
iotpassword = 'your_device_password'

tenantusername = 'your_tenant_email'
tenantpassword = 'your_tenant_password'
```

`tenantusername` / `tenantpassword` are only needed by `examples/01-getting-started/token_claim.py`. Everything else uses the `iot*` pair.

These credentials are issued once SandGrain has created your Tenant user account. Contact **<support@sandgrain.eu>** to get one.

### Protecting your credentials

`SandGrain_Credentials.py` ships as a template that you edit **in place** — and it is **not** covered by `.gitignore`. If you vendor this project into your own repository, add it before you fill anything in:

```bash
echo 'SandGrain_Credentials.py' >> .gitignore
```

Without that, the first commit after you add real credentials will publish them.

---

## 2. Interface

Set the interface in `CyberRock_Config.py`:

```python
interface = 'USB'      # or 'SPI'
serial_port = None     # None = platform default
```

| Interface | Platforms | Notes |
| --- | --- | --- |
| `USB` | Linux, Windows, macOS | 115200 baud. Default port `/dev/ttyACM0` (Linux/macOS) or `COM3` (Windows). |
| `SPI` | Linux / Raspberry Pi only | 10 MHz, mode 0, manual CS on GPIO 22. On Windows this falls back to USB automatically with a warning. |

To see what ports are available:

```python
import CyberRock_Config as config
print(config.list_serial_ports())
```

### SPI wiring — Raspberry Pi 4 to token (SGT1001)

| Raspberry Pi pin | Token pin |
| --- | --- |
| Pin 17 (3.3 V) | VDD (pin 8) |
| Pin 25 (GND) | VSS (pin 4) |
| Pin 19 (BCM 10) | MOSI (pin 5) |
| Pin 21 (BCM 9) | MISO (pin 2) |
| Pin 23 (BCM 11) | CLK (pin 6) |
| Pin 15 (BCM 22) | CSN (pin 1) |

Enable SPI first:

```bash
sudo raspi-config      # Interface Options -> SPI -> Enable
```

---

## 3. Environment

Also in `CyberRock_Config.py`:

```python
ENVIRONMENT = 'sandbox'      # or 'production'
```

| Environment | Device API |
| --- | --- |
| `sandbox` | `https://device-api.sandbox.sandgrain.io/` |
| `production` | `https://device-api.cyberrock.sandgrain.io/` |

The tenant API URL is derived automatically by substituting `tenant-api` for `device-api`.

---

## 4. Dependencies

**Python 3.9 or newer.** The hard floor is the dict merge operator (`|`) used throughout `CyberRock_Cloud.py` and the walrus operator in the file-hashing helper.

### Linux / Raspberry Pi

```bash
sudo apt-get update
sudo apt-get install -y python3-pip python3-rpi.gpio python3-spidev
pip3 install requests pyserial
```

`python3-rpi.gpio` and `python3-spidev` are only needed for the SPI interface.

### Windows / macOS

```bash
pip install requests pyserial
```

### For the `_rsa2048` examples only

```bash
pip install cryptography
```

---

## Checking your setup

```bash
python examples/01-getting-started/token_id.py
```

| What you see | What it means |
| --- | --- |
| A 64-character TID | Interface is correct. Move on to a cloud flow. |
| `No response from token on serial port …` | Wrong port, or the token is not connected. Check `list_serial_ports()`. |
| `ModuleNotFoundError: No module named 'serial'` | `pip install pyserial`. |
| Hangs indefinitely | See the polling note in [known-issues.md](known-issues.md). |
