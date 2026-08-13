"""
Ask the cloud what a boot chain's attestation value *should* be.

WHEN TO USE   Provisioning and diagnostics. Instead of submitting a value for
              a yes/no verdict, you ask the cloud to compute the expected
              attestation for a given chain -- useful for baking a known-good
              reference into a manufacturing test, or for working out which
              stage of a failing chain diverged.
YOU NEED      A connected token, IoT device credentials, network access.
THIS PROVES   The locally computed attestation value matches the cloud's
              independent derivation for the same chain.
COST          3 cloud calls (the last one polls), 4 token transfers.

Three levels here, versus two in the other scripts in this folder -- the
chain length is yours to choose.
"""

import sys
import hashlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import CyberRock_Cloud as cloud
import CyberRock_Token as token
import CyberRock_Config as config
import SandGrain_Credentials as credentials


def main():

    # 1. CONFIGURE -- interface (SPI/USB) and environment come from CyberRock_Config
    config.init()

    # 2. CONNECT -- read the token's identity
    tid = token.get_tid()
    print(f"TID: {tid}")

    # 3. RUN THE FLOW
    # Simulate firmware hashes
    hash_func = hashlib.new('sha256')
    hash_func.update(b'firmware_level_2_content')
    fw2hash = hash_func.hexdigest()

    hash_func2 = hashlib.new('sha256')
    hash_func2.update(b'firmware_level_3_content')
    fw3hash = hash_func2.hexdigest()

    hash_func3 = hashlib.new('sha256')
    hash_func3.update(b'firmware_level_4_content')
    fw4hash = hash_func3.hexdigest()

    # NOTE: the three assignments below overwrite the computed hashes above,
    # making that computation dead. Preserved verbatim during the restructure.
    # See docs/known-issues.md.
    fw2hash = '10276c01e17911a793eed9382786ea2a8227b25a931876026302c9bce004b40e'
    fw3hash = '20276c01e17911a793eed9382786ea2a8227b25a931876026302c9bce004b40e'
    fw4hash = '30276c01e17911a793eed9382786ea2a8227b25a931876026302c9bce004b40e'

    print(f"FW2 hash: {fw2hash}")
    print(f"FW3 hash: {fw3hash}")
    print(f"FW4 hash: {fw4hash}")

    # The device picks the starting value itself.
    # NOTE: make_challenge() has one-second granularity. See docs/known-issues.md.
    boot_cw = token.make_challenge()

    print(f"BootCW: {boot_cw}")

    # Compute attestation locally:
    # Level 1: CW1 = BootCW XOR FW2hash
    cw1 = "".join(["%x" % (int(x, 16) ^ int(y, 16)) for (x, y) in zip(boot_cw[:len(fw2hash)], fw2hash)])
    rw1 = token.do_host_auth(token.hex_to_bytes(cw1))
    chain_value = rw1 + rw1

    # Level 2: CW2 = chain_value XOR FW3hash
    cw2 = "".join(["%x" % (int(x, 16) ^ int(y, 16)) for (x, y) in zip(chain_value[:len(fw3hash)], fw3hash)])
    rw2 = token.do_host_auth(token.hex_to_bytes(cw2))
    chain_value = rw2 + rw2

    # Level 3: CW3 = chain_value XOR FW4hash
    cw3 = "".join(["%x" % (int(x, 16) ^ int(y, 16)) for (x, y) in zip(chain_value[:len(fw4hash)], fw4hash)])
    rw3 = token.do_host_auth(token.hex_to_bytes(cw3))
    attestation_local = rw3

    print(f"Attestation (local): {attestation_local}")

    # Prepare chain data
    l_tid = [tid, tid, tid]
    l_data = [fw2hash, fw3hash, fw4hash]

    iotaccesstoken, iotid = cloud.do_device_login(
        credentials.cloudflaretokens, credentials.iotusername, credentials.iotpassword, False)

    # Request cloud to compute expected attestation HRW
    transactionid = cloud.do_device_requestSecureBootAttestationHRW(
        credentials.cloudflaretokens, iotaccesstoken,
        l_tid, l_data, boot_cw, False, False)

    # Poll for result
    attestation_cloud = cloud.do_device_checkRequestSecureBootAttestationHRWStatus(
        credentials.cloudflaretokens, iotaccesstoken, transactionid, False, False)

    print(f"Attestation (cloud): {attestation_cloud}")

    # 4. ┌─ YOUR INTEGRATION POINT ──────────────────────────────────────┐
    #    │ `attestation_cloud` is the reference value for this chain.    │
    #    │ Record it at provisioning time and compare against it later.  │
    #    └───────────────────────────────────────────────────────────────┘
    if attestation_local == attestation_cloud:
        print("\nSecure Boot Attestation HRW verified - attestation value correct")
    else:
        print("\nSecure Boot Attestation HRW mismatch!")


if __name__ == "__main__":
    main()
