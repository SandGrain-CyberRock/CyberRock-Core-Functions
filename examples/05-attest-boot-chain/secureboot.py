"""
Attest a multi-stage boot chain -- cloud issues the starting challenge.

WHEN TO USE   You want to prove which firmware actually ran, not just that
              the device is genuine. Each boot stage's hash is folded into a
              chain; changing any stage changes the final value, so a single
              comparison covers the whole chain.
YOU NEED      A connected token, IoT device credentials, network access.
THIS PROVES   The device ran exactly the firmware whose hashes it declared,
              in that order, on this token.
COST          4 cloud calls (the last one polls), 3 token transfers.

The chain: each level XORs the running value with the next firmware hash and
feeds the result through the token. Replace the two demo hashes with real
digests of your boot stages.
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
    # Stand-in firmware digests. Replace with real SHA-256 of your boot stages
    # (see secureboot_host.py for a file-hashing helper).
    hash_func = hashlib.new('sha256')
    hash_func.update(b'firmware_level_2_content')
    fw2hash = hash_func.hexdigest()

    hash_func2 = hashlib.new('sha256')
    hash_func2.update(b'firmware_level_3_content')
    fw3hash = hash_func2.hexdigest()

    print(f"FW2 hash: {fw2hash}")
    print(f"FW3 hash: {fw3hash}")

    # Chain structure: 2 TIDs (same token), 2 firmware hashes as data
    l_tid = [tid, tid]
    l_data = [fw2hash, fw3hash]

    iotaccesstoken, iotid = cloud.do_device_login(
        credentials.cloudflaretokens, credentials.iotusername, credentials.iotpassword, False)

    # Step 1: Request attestation CW from cloud
    cw, transactionid = cloud.do_device_requestSecureBootAttestationCW(
        credentials.cloudflaretokens, iotaccesstoken, l_tid, l_data, False, False)

    print(f"Attestation CW: {cw}")
    print(f"Transaction ID: {transactionid}")

    # Step 2: Chain through firmware levels
    # Level 1: CW1 = CW XOR FW2hash
    cw1 = "".join(["%x" % (int(x, 16) ^ int(y, 16)) for (x, y) in zip(cw[:len(fw2hash)], fw2hash)])
    rw1 = token.do_host_auth(token.hex_to_bytes(cw1))
    chain_value = rw1 + rw1

    # Level 2: CW2 = chain_value XOR FW3hash
    cw2 = "".join(["%x" % (int(x, 16) ^ int(y, 16)) for (x, y) in zip(chain_value[:len(fw3hash)], fw3hash)])
    rw2 = token.do_host_auth(token.hex_to_bytes(cw2))
    attestation_value = rw2

    print(f"Attestation value: {attestation_value}")

    # Step 3: Submit attestation RW to cloud
    cloud.do_device_replySecureBootAttestationRW(
        credentials.cloudflaretokens, iotaccesstoken,
        l_tid, l_data, cw, attestation_value, transactionid, False, False)

    # Step 4: Check attestation status
    authenticationresult, claimid = cloud.do_device_checkRequestSecureBootAttestationStatus(
        credentials.cloudflaretokens, iotaccesstoken, transactionid, False, False)

    print(f"\nAttestation result: {authenticationresult}")

    # 4. ┌─ YOUR INTEGRATION POINT ──────────────────────────────────────┐
    #    │ A failure means the declared firmware chain does not match    │
    #    │ what the cloud expects -- halt the boot or quarantine.        │
    #    └───────────────────────────────────────────────────────────────┘
    if authenticationresult == 'AUTH_OK' or authenticationresult == 'CLAIM_TOKEN':
        print("Secure Boot Attestation verified")
    else:
        print("Secure Boot Attestation failed!")


if __name__ == "__main__":
    main()
