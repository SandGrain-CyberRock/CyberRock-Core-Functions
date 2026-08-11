"""
Mutual authentication -- device issues the challenge, both sides prove themselves.

WHEN TO USE   Same trust requirement as mutual_auth.py, but the
              device controls when the exchange starts and supplies its own
              challenge. Preferred when the device is the active party.
YOU NEED      A connected token, IoT device credentials, network access.
THIS PROVES   Both directions: the cloud accepted the token's HRW, AND the
              cloud returned an HRW2 the device could independently
              reproduce -- which only a party holding the same secret can do.
COST          3 cloud calls (the last one polls), 3 token transfers.
"""

import sys
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
    # The host picks its own challenge. NOTE: make_challenge() has one-second
    # granularity -- use a random nonce in production. See docs/known-issues.md.
    hcw = token.make_challenge()

    # Get HRW from token
    hrw = token.do_host_auth(token.hex_to_bytes(hcw))
    print(f"HRW: {hrw}")

    iotaccesstoken, iotid = cloud.do_device_login(
        credentials.cloudflaretokens, credentials.iotusername, credentials.iotpassword, False)

    # Step 1: Submit host auth to cloud and request mutual proof
    transactionid = cloud.do_device_hostmutualauth_request(
        credentials.cloudflaretokens, iotaccesstoken, tid, hcw, hrw, False)

    # Step 2: Poll for result — cloud returns auth status + its own proof, HRW2
    authenticationresult, hrw2_cloud, claimid = cloud.do_device_hostmutualauth_checkstatus(
        credentials.cloudflaretokens, iotaccesstoken, transactionid, False, False)

    print(f"\nCloud auth result: {authenticationresult}")
    print(f"Cloud HRW2: {hrw2_cloud}")

    # Step 3: Reproduce HRW2 locally = HMAC(HRW || HRW)
    hrw2_local = token.do_host_auth(token.hex_to_bytes(hrw + hrw))
    print(f"Local HRW2: {hrw2_local}")

    # 4. ┌─ YOUR INTEGRATION POINT ──────────────────────────────────────┐
    #    │ BOTH conditions must hold. A good auth result with a          │
    #    │ mismatched HRW2 means you are talking to an impostor.         │
    #    └───────────────────────────────────────────────────────────────┘
    if ((authenticationresult == 'AUTH_OK') or (authenticationresult == 'CLAIM_TOKEN')) and (hrw2_cloud == hrw2_local):
        print('\nHost Mutual Authentication successful')
    else:
        print('\nHost Mutual Authentication failed!')
        if authenticationresult not in ('AUTH_OK', 'CLAIM_TOKEN'):
            print(f"  Cloud rejected host auth: {authenticationresult}")
        if hrw2_cloud != hrw2_local:
            print(f"  HRW2 mismatch — cloud not authenticated")


if __name__ == "__main__":
    main()
