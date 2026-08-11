"""
Mutual authentication -- cloud issues the challenge, both sides prove themselves.

WHEN TO USE   When the device must not trust the endpoint it is talking to.
              Plain authentication proves the device to the cloud; this also
              proves the cloud to the device, defeating an impostor server
              that could otherwise collect challenges.
YOU NEED      A connected token, IoT device credentials, network access.
THIS PROVES   Both directions: the cloud accepted the token's RW, AND the
              cloud returned an HRW2 the device could independently
              reproduce -- which only a party holding the same secret can do.
COST          4 cloud calls (the last one polls), 3 token transfers.
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
    iotaccesstoken, iotid = cloud.do_device_login(
        credentials.cloudflaretokens, credentials.iotusername, credentials.iotpassword, False)

    # Step 1: Request CW from cloud
    cw, transactionid = cloud.do_device_mutualauth_requestcw(
        credentials.cloudflaretokens, iotaccesstoken, tid, False, False)

    print(f"CW: {cw}")

    # Step 2: Get RW from token
    rw = token.do_token_auth(token.hex_to_bytes(cw))
    print(f"RW: {rw}")

    # Step 3: Submit RW to cloud
    cloud.do_device_mutualauth_replyrw(
        credentials.cloudflaretokens, iotaccesstoken, tid, cw, rw, transactionid, False, False)

    # Step 4: Check status — cloud returns auth result + its own proof, HRW2
    authenticationresult, hrw2_cloud, claimid = cloud.do_device_mutualauth_checkstatus(
        credentials.cloudflaretokens, iotaccesstoken, transactionid, False, False)

    print(f"\nCloud auth result: {authenticationresult}")
    print(f"Cloud HRW2: {hrw2_cloud}")

    # Step 5: Reproduce HRW2 locally = HMAC(RW || RW)
    hrw2_local = token.do_host_auth(token.hex_to_bytes(rw + rw))
    print(f"Local HRW2: {hrw2_local}")

    # 4. ┌─ YOUR INTEGRATION POINT ──────────────────────────────────────┐
    #    │ BOTH conditions must hold. A good auth result with a          │
    #    │ mismatched HRW2 means you are talking to an impostor.         │
    #    └───────────────────────────────────────────────────────────────┘
    if ((authenticationresult == 'AUTH_OK') or (authenticationresult == 'CLAIM_TOKEN')) and (hrw2_cloud == hrw2_local):
        print('\nMutual Authentication successful')
    else:
        print('\nMutual Authentication failed!')
        if authenticationresult not in ('AUTH_OK', 'CLAIM_TOKEN'):
            print(f"  Cloud rejected token: {authenticationresult}")
        if hrw2_cloud != hrw2_local:
            print(f"  HRW2 mismatch — cloud not authenticated")


if __name__ == "__main__":
    main()
