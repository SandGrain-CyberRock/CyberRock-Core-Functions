"""
Attest a multi-stage boot chain -- device issues the starting challenge.

WHEN TO USE   Attestation at boot time, before the device has any reason to
              trust the network. The device picks its own BootCW, walks the
              chain locally, and submits the result for verification once it
              is online.
YOU NEED      A connected token, IoT device credentials, network access.
THIS PROVES   The device ran exactly the firmware whose hashes it declared,
              in that order, on this token.
COST          3 cloud calls (the last one polls), 3 token transfers.

`compute_file_hash` below is the helper to use on real boot images; the demo
substitutes fixed strings so the example runs anywhere.
"""

import sys
import hashlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import CyberRock_Cloud as cloud
import CyberRock_Token as token
import CyberRock_Config as config
import SandGrain_Credentials as credentials


def compute_file_hash(file_path, algorithm='sha256'):
    """Compute the hash of a file. Use this on your real boot images."""
    hash_func = hashlib.new(algorithm)
    with open(file_path, 'rb') as file:
        while chunk := file.read(8192):
            hash_func.update(chunk)
    return hash_func.hexdigest()


def main():

    # 1. CONFIGURE -- interface (SPI/USB) and environment come from CyberRock_Config
    config.init()

    # 2. CONNECT -- read the token's identity
    tid = token.get_tid()
    print(f"TID: {tid}")

    # 3. RUN THE FLOW
    # Stand-in firmware digests. Swap in compute_file_hash('/boot/stage2.bin')
    # and friends to attest real images.
    hash_func = hashlib.new('sha256')
    hash_func.update(b'firmware_level_2_content')
    fw2hash = hash_func.hexdigest()

    hash_func2 = hashlib.new('sha256')
    hash_func2.update(b'firmware_level_3_content')
    fw3hash = hash_func2.hexdigest()

    print(f"FW2 hash: {fw2hash}")
    print(f"FW3 hash: {fw3hash}")

    # The device picks the starting value itself.
    # NOTE: make_challenge() has one-second granularity. See docs/known-issues.md.
    boot_cw = token.make_challenge()

    print(f"BootCW: {boot_cw}")

    # Chain computation:
    # Level 1: CW1 = BootCW XOR FW2hash, RW1 = token.do_host_auth(CW1)
    cw1 = "".join(["%x" % (int(x, 16) ^ int(y, 16)) for (x, y) in zip(boot_cw[:len(fw2hash)], fw2hash)])
    rw1 = token.do_host_auth(token.hex_to_bytes(cw1))
    chain_value = rw1 + rw1

    # Level 2: CW2 = chain_value XOR FW3hash, RW2 = token.do_host_auth(CW2)
    cw2 = "".join(["%x" % (int(x, 16) ^ int(y, 16)) for (x, y) in zip(chain_value[:len(fw3hash)], fw3hash)])
    rw2 = token.do_host_auth(token.hex_to_bytes(cw2))
    attestation_value = rw2

    print(f"Attestation value: {attestation_value}")

    # Prepare chain data for cloud
    l_tid = [tid, tid]
    l_data = [fw2hash, fw3hash]

    iotaccesstoken, iotid = cloud.do_device_login(
        credentials.cloudflaretokens, credentials.iotusername, credentials.iotpassword, False)

    # Submit host secure boot attestation
    transactionid = cloud.do_device_requestHostSecureBootAttestation(
        credentials.cloudflaretokens, iotaccesstoken,
        l_tid, l_data, boot_cw, attestation_value, False, False)

    # Poll for result
    authenticationresult = cloud.do_device_checkHostSecureBootAttestationStatus(
        credentials.cloudflaretokens, iotaccesstoken, transactionid, False, False)

    print(f"\nAttestation result: {authenticationresult}")

    # 4. ┌─ YOUR INTEGRATION POINT ──────────────────────────────────────┐
    #    │ A failure means the declared firmware chain does not match    │
    #    │ what the cloud expects -- halt the boot or quarantine.        │
    #    └───────────────────────────────────────────────────────────────┘
    if authenticationresult == 'AUTH_OK':
        print("Host Secure Boot Attestation verified")
    else:
        print("Host Secure Boot Attestation failed!")


if __name__ == "__main__":
    main()
