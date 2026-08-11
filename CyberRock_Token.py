"""
CyberRock_Token.py — Hardware abstraction layer for the SandGrain CyberRock security token.

Supports SPI (Raspberry Pi via spidev/RPi.GPIO) and USB serial interfaces.
USB serial works cross-platform (Linux and Windows).
Currently configured for SGT1001 command codes; SGA variants are retained as comments.

Usage:
    import CyberRock_Token as token
    token.init('SPI', cs_pin=22)                      # Raspberry Pi with SPI
    token.init('USB', serial_port='/dev/ttyACM0')     # Linux USB
    token.init('USB', serial_port='COM3')             # Windows USB

    tid        = token.get_tid()
    rw         = token.do_token_auth(challenge)
    rw, ek     = token.do_token_auth_ek(challenge)
    hrw        = token.do_host_auth(host_challenge)
    hrw, ek    = token.do_host_auth_ek(host_challenge)
    tid, hcw, hrw = token.do_host_auth_ext(host_challenge)
    pass, *_   = token.do_bist()

All challenge inputs are lists of bytes, length API_I_CHAL_LENGTH (32).
All response values are hex strings.

Call init() once before any other function, typically via CyberRock_Config.py.

Platform notes:
    - SPI interface requires spidev and RPi.GPIO (Linux/Raspberry Pi only)
    - USB interface requires pyserial (cross-platform: Linux, Windows, macOS)
    - On Windows, use COM port names (e.g., 'COM3', 'COM4')
"""

l_command_ident = [0x01, 0x00, 0x00, 0x00]
l_command_bist  = [0xff, 0x00, 0x00, 0x00] #pv-2024-03-13: 0x80 for SGA
l_command_cr    = [0x03, 0x00, 0x08, 0x00]
l_command_cr_ek = [0x07, 0x00, 0x08, 0x00]
l_command_hcr    = [0x05, 0x00, 0x08, 0x00] #jd 0x05 for SGB
l_command_hcr_ek = [0x06, 0x00, 0x08, 0x00] #jd 0x06 for SGB
#l_command_hcr    = [0x03, 0x00, 0x08, 0x00] #jd 0x03 for SGA
#l_command_hcr_ek = [0x07, 0x00, 0x08, 0x00] #jd 0x07 for SGA

API_I_IDENT_PART1_START  =  5
API_I_IDENT_PART1_LENGTH = 16
API_I_IDENT_PART2_START  = 21 # API_I_IDENT_PART1_START + API_I_IDENT_PART1_LENGTH
API_I_IDENT_PART2_LENGTH = 16

API_I_IDENT_START        =  5
API_I_IDENT_LENGTH       = 32

API_I_CHAL_START         = 38 # API_I_IDENT_START       + API_I_IDENT_LENGTH        + 1
API_I_CHAL_LENGTH        = 32                                                       
                                                                                    
API_I_CHAL_PART1_START   = 38 # API_I_IDENT_START       + API_I_IDENT_LENGTH        + 1
API_I_CHAL_PART1_LENGTH  = 16                                                       
API_I_CHAL_PART2_START   = 54 # API_I_CHAL_PART1_START  + API_I_CHAL_PART1_LENGTH   
API_I_CHAL_PART2_LENGTH  = 16                                                       
                                                                                    
API_I_RESP_START         = 71 # API_I_CHAL_START        + API_I_CHAL_LENGTH         + 1
API_I_RESP_LENGTH        = 16                                                       
API_I_EK_START           = 87 # API_I_RESP_START        + API_I_RESP_LENGTH         
API_I_EK_LENGTH          = 16                                                       
                                                                                    
API_I_RWL_PART1_START    = 38 # API_I_IDENT_START       + API_I_IDENT_LENGTH        + 1
API_I_RWL_PART1_LENGTH   = 16
API_I_RWL_PART2_START    = 54 # API_I_RWL_PART1_START   + API_I_RWL_PART1_LENGTH
API_I_RWL_PART2_LENGTH   = 16

API_I_BIST               = 71


import hashlib as _hashlib
import platform as _platform
import time as _time

_do_transfer_l = None

# Platform-appropriate default serial port
_DEFAULT_SERIAL_PORT = 'COM3' if _platform.system() == 'Windows' else '/dev/ttyACM0'

def init(interface='SPI', spi_bus=0, spi_device=0, spi_speed=10_000_000,
         serial_port=None, cs_pin=22):
    """Initialize the token communication interface.

    Args:
        interface: 'SPI' or 'USB'. SPI is only available on Linux/Raspberry Pi.
        spi_bus: SPI bus number (default 0, SPI only).
        spi_device: SPI device number (default 0, SPI only).
        spi_speed: SPI clock speed in Hz (default 10 MHz, SPI only).
        serial_port: Serial port name. Defaults to 'COM3' on Windows,
                     '/dev/ttyACM0' on Linux. Only used for USB interface.
        cs_pin: GPIO pin for chip select (default 22, SPI only).
    """
    global _do_transfer_l

    if serial_port is None:
        serial_port = _DEFAULT_SERIAL_PORT

    if interface == 'SPI':
        import spidev
        import RPi.GPIO as GPIO
        GPIO.setwarnings(False)
        GPIO.setmode(GPIO.BCM)
        GPIO.setup(cs_pin, GPIO.OUT)
        GPIO.output(cs_pin, GPIO.HIGH)

        def do_transfer_l(l):
            GPIO.output(cs_pin, GPIO.LOW)
            spi = spidev.SpiDev(spi_bus, spi_device)
            spi.max_speed_hz = spi_speed
            resp = spi.xfer(l)
            spi.close()
            GPIO.output(cs_pin, GPIO.HIGH)
            if len(resp) == 0:
                raise IOError("No response from token on SPI port")
            return resp

    elif interface == 'USB':
        import serial

        def do_transfer_l(l):
            ser = serial.Serial(serial_port, baudrate=115200, timeout=0.5)
            frame = ''.join('%02x' % e for e in l) + '\r'
            ser.write(frame.encode('utf-8'))
            resp = ser.read(512)
            ser.close()
            if len(resp) == 0:
                raise IOError(f"No response from token on serial port {serial_port}")
            # Strip any trailing CR/LF (Windows may add \r\n)
            resp_str = resp.decode('utf-8', errors='ignore').strip()
            if len(resp_str) == 0:
                raise IOError(f"Empty response from token on serial port {serial_port}")
            return [int(resp_str[i:i+2], 16) for i in range(0, len(resp_str), 2)]

    else:
        raise ValueError(f"Unknown interface: {interface!r}")

    _do_transfer_l = do_transfer_l

def _transfer_l(l):
    if _do_transfer_l is None:
        raise RuntimeError("CyberRock_Token not initialized — call init() first")
    return _do_transfer_l(l)

def list_invert(l): return [(~e)&0xFF for e in l]

def hex_to_bytes(s):
    """Convert a hex string (no leading 0x) into a list of byte values.

    Every challenge and response crosses the token boundary as hex; the
    do_* functions below take byte lists. This is the bridge.

        >>> hex_to_bytes('ff00')
        [255, 0]
    """
    return [int(s[i:i+2], 16) for i in range(0, len(s), 2)]

def make_challenge():
    """Generate a 32-byte host challenge (HCW) as a 64-char hex string.

    SHA-256 over a formatted UTC timestamp. NOTE: the timestamp has
    one-second granularity, so two calls within the same second return the
    SAME challenge. Production integrations should use a random nonce or a
    monotonic counter instead. See docs/known-issues.md.
    """
    curr = _time.time()
    curr_time = _time.strftime("%a %d %b %Y %H %M %S", _time.gmtime(curr))
    hash_func = _hashlib.new('sha256')
    hash_func.update(str(curr_time).encode('utf-8'))
    return hash_func.hexdigest()

#assemble
def assemble_bist_l()         : return l_command_bist +[0]*68
def assemble_id_l()           : return l_command_ident + [0] + [0]*32
def assemble_cw_l(l_challenge): return l_command_cr    + [0] + l_challenge + [0] + [0]*49 # CR 65-16
def assemble_ek_l(l_challenge): return l_command_cr_ek + [0] + l_challenge + [0] + [0]*65 # CR_EK 65
def assemble_hcw_l(l_challenge): return l_command_hcr    + [0] + l_challenge + [0] + [0]*49 # CR 65-16
def assemble_hek_l(l_challenge): return l_command_hcr_ek + [0] + l_challenge + [0] + [0]*65 # CR_EK 65

# disassemble
def disassemble_l_bist(l_r):
    l_pcc       = l_r[API_I_IDENT_PART1_START : API_I_IDENT_PART1_START  + API_I_IDENT_PART1_LENGTH]
    l_id        = l_r[API_I_IDENT_PART2_START : API_I_IDENT_PART2_START  + API_I_IDENT_PART2_LENGTH]
    l_rw        = l_r[API_I_RWL_PART1_START : API_I_RWL_PART1_START  + API_I_RWL_PART1_LENGTH]
    l_ek        = l_r[API_I_RWL_PART2_START : API_I_RWL_PART2_START  + API_I_RWL_PART2_LENGTH]
    i_pass      = l_r[API_I_BIST]
    b_pass = 1 if i_pass == 0x50 else 0
    return b_pass, l_pcc, l_id, l_rw, l_ek
    
def disassemble_l_id(l_r):
    l_pcc       = l_r[API_I_IDENT_PART1_START : API_I_IDENT_PART1_START  + API_I_IDENT_PART1_LENGTH]                
    l_id        = l_r[API_I_IDENT_PART2_START : API_I_IDENT_PART2_START  + API_I_IDENT_PART2_LENGTH]                
    return l_pcc, l_id
  
def disassemble_l_rw(l_r):
    l_pcc       = l_r[API_I_IDENT_PART1_START : API_I_IDENT_PART1_START  + API_I_IDENT_PART1_LENGTH]                
    l_id        = l_r[API_I_IDENT_PART2_START : API_I_IDENT_PART2_START  + API_I_IDENT_PART2_LENGTH]                
    l_rw        = l_r[API_I_RESP_START        : API_I_RESP_START         + API_I_RESP_LENGTH       ]          
    return l_pcc, l_id, l_rw

def disassemble_l_rw_ext(l_r):
    l_pcc       = l_r[API_I_IDENT_PART1_START : API_I_IDENT_PART1_START  + API_I_IDENT_PART1_LENGTH]
    l_id        = l_r[API_I_IDENT_PART2_START : API_I_IDENT_PART2_START  + API_I_IDENT_PART2_LENGTH]
    l_cw        = l_r[API_I_CHAL_PART1_START  : API_I_CHAL_START         + API_I_CHAL_LENGTH       ]
    l_rw        = l_r[API_I_RESP_START        : API_I_RESP_START         + API_I_RESP_LENGTH       ]
    return l_pcc, l_id, l_cw, l_rw

# def disassemble_l_ek(l_r):
#     l_pcc       = l_r[API_I_IDENT_PART1_START : API_I_IDENT_PART1_START  + API_I_IDENT_PART1_LENGTH]
#     l_id        = l_r[API_I_IDENT_PART2_START : API_I_IDENT_PART2_START  + API_I_IDENT_PART2_LENGTH]
#     l_ek        = l_r[API_I_EK_START          : API_I_EK_START           + API_I_EK_LENGTH         ]
#     return l_pcc, l_id, l_ek

def disassemble_l_rwek(l_r):
    l_pcc       = l_r[API_I_IDENT_PART1_START : API_I_IDENT_PART1_START  + API_I_IDENT_PART1_LENGTH]                
    l_id        = l_r[API_I_IDENT_PART2_START : API_I_IDENT_PART2_START  + API_I_IDENT_PART2_LENGTH]                
    l_rw        = l_r[API_I_RESP_START        : API_I_RESP_START         + API_I_RESP_LENGTH       ]  
    l_ek        = l_r[API_I_EK_START          : API_I_EK_START           + API_I_EK_LENGTH         ]                  
    return l_pcc, l_id, l_rw, l_ek

# do bist
def do_bist():
    l_r = _transfer_l(assemble_bist_l())
    b_pass, l_pcc, l_id, l_rw, l_ek = disassemble_l_bist(l_r)
    return b_pass, l_pcc, l_id, l_rw, l_ek

# get TID only
def get_tid():
    l_r = _transfer_l(assemble_id_l())
    l_pcc, l_id = disassemble_l_id(l_r)
#    l_tid = l_pcc + l_id
    s_pcc = ''.join('%02x' % e for e in l_pcc)
    s_id = ''.join('%02x' % e for e in l_id)
    s_tid = s_pcc + s_id
    return s_tid

#get RW only
def do_token_auth(cw_l):
    if len(cw_l) != API_I_CHAL_LENGTH:
        raise ValueError(f"Challenge must be {API_I_CHAL_LENGTH} bytes, got {len(cw_l)}")
    l_r = _transfer_l(assemble_cw_l(cw_l))
    l_pcc, l_id, l_rw = disassemble_l_rw(l_r)
    s_rw = ''.join('%02x' % e for e in l_rw)
    return s_rw

def do_host_auth(hcw_l):
    if len(hcw_l) != API_I_CHAL_LENGTH:
        raise ValueError(f"Challenge must be {API_I_CHAL_LENGTH} bytes, got {len(hcw_l)}")
    l_r = _transfer_l(assemble_hcw_l(hcw_l))
    l_pcc, l_id, l_hrw = disassemble_l_rw(l_r)
    s_hrw = ''.join('%02x' % e for e in l_hrw)
    return s_hrw

#return everything from token communication
def do_host_auth_ext(hcw_l):
    if len(hcw_l) != API_I_CHAL_LENGTH:
        raise ValueError(f"Challenge must be {API_I_CHAL_LENGTH} bytes, got {len(hcw_l)}")
    l_r = _transfer_l(assemble_hcw_l(hcw_l))
    l_pcc, l_id, l_hcw, l_hrw = disassemble_l_rw_ext(l_r)
    s_pcc = ''.join('%02x' % e for e in l_pcc)
    s_id = ''.join('%02x' % e for e in l_id)
    s_tid = s_pcc + s_id
    s_hcw = ''.join('%02x' % e for e in l_hcw)
    s_hrw = ''.join('%02x' % e for e in l_hrw)
    return s_tid, s_hcw, s_hrw

#get RW and EK
def do_token_auth_ek(cw_l):
    if len(cw_l) != API_I_CHAL_LENGTH:
        raise ValueError(f"Challenge must be {API_I_CHAL_LENGTH} bytes, got {len(cw_l)}")
    l_r = _transfer_l(assemble_ek_l(cw_l))
    l_pcc, l_id, l_rw, l_ek = disassemble_l_rwek(l_r)        
    s_rw = ''.join('%02x' % e for e in l_rw)
    s_ek = ''.join('%02x' % e for e in l_ek)
    return s_rw, s_ek

def do_host_auth_ek(hcw_l):
    if len(hcw_l) != API_I_CHAL_LENGTH:
        raise ValueError(f"Challenge must be {API_I_CHAL_LENGTH} bytes, got {len(hcw_l)}")
    l_r = _transfer_l(assemble_hek_l(hcw_l))
    l_pcc, l_id, l_hrw, l_ek = disassemble_l_rwek(l_r)
    s_hrw = ''.join('%02x' % e for e in l_hrw)
    s_ek = ''.join('%02x' % e for e in l_ek)
    return s_hrw, s_ek
