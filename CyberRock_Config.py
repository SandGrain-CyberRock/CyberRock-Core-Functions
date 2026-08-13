# CyberRock_Config
# Central configuration for hardware interface and cloud environment.
# Cross-platform: supports Linux (SPI + USB) and Windows (USB only).

import platform

# --- Platform Detection ---
IS_WINDOWS = platform.system() == 'Windows'
IS_LINUX = platform.system() == 'Linux'

# --- Interface Configuration ---
# Set to one of: 'SPI' or 'USB'
# Note: SPI is only available on Linux/Raspberry Pi.
#       On Windows, SPI will automatically fall back to USB with a warning.
#interface = 'SPI'
interface = 'USB'

# --- Serial Port Configuration ---
# Set to the appropriate serial port for your platform.
# Linux default: '/dev/ttyACM0'
# Windows default: 'COM3'
# Set to None for automatic platform-based default.
serial_port = None

# --- Environment Configuration ---
# Set to one of: 'sandbox', 'uat', 'production'
ENVIRONMENT = 'uat'
#ENVIRONMENT = 'sandbox'
#ENVIRONMENT = 'production'

ENVIRONMENT_URLS = {
    'sandbox':    'https://device-api.sandbox.sandgrain.io/',
    'uat':        'https://device-api-uat.sandgrain.dev/',
    'production': 'https://device-api.cyberrock.sandgrain.io/',
}

def get_environment_url():
    """Return the base URL for the configured environment."""
    url = ENVIRONMENT_URLS.get(ENVIRONMENT)
    if url is None:
        raise ValueError(f"Unknown environment '{ENVIRONMENT}'. Choose from: {list(ENVIRONMENT_URLS)}")
    return url


def get_default_serial_port():
    """Return the platform-appropriate default serial port."""
    if IS_WINDOWS:
        return 'COM3'
    return '/dev/ttyACM0'


def list_serial_ports():
    """List available serial ports on this system.

    Returns a list of port name strings (e.g., ['COM3', 'COM4'] on Windows
    or ['/dev/ttyACM0', '/dev/ttyUSB0'] on Linux).

    Requires pyserial to be installed.
    """
    from serial.tools import list_ports
    return [p.device for p in list_ports.comports()]


import CyberRock_Token as token


def init():
    """Initialize the CyberRock token with the configured interface.

    On Windows, if SPI is configured, automatically falls back to USB
    since SPI is not available on Windows.
    """
    _interface = interface
    _serial_port = serial_port if serial_port is not None else get_default_serial_port()

    if _interface == 'SPI' and IS_WINDOWS:
        print("WARNING: SPI interface not available on Windows. Falling back to USB.")
        _interface = 'USB'

    if _interface == 'SPI':
        token.init(
            interface='SPI',
            cs_pin=22,
            spi_bus=0,
            spi_device=0,
            spi_speed=10_000_000,
        )
    elif _interface == 'USB':
        token.init(
            interface='USB',
            serial_port=_serial_port,
        )
    else:
        raise ValueError(f"Unknown interface '{_interface}'. Choose 'SPI' or 'USB'.")
