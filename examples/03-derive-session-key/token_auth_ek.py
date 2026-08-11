"""
Derive a shared session key (EK) -- cloud issues the challenge.

WHEN TO USE   You need a symmetric key that both the device and the cloud
              hold, without ever transmitting it. Authentication and key
              derivation happen in the same exchange.
YOU NEED      A connected token, IoT device credentials, network access.
THIS PROVES   The token authenticated AND both sides independently derived
              the same 16-byte Ephemeral Key -- one from the hardware, one
              from the HSM-backed CyberRock Enclave.
COST          4 cloud calls (the last one polls), 2 token transfers.

The EK travels over HTTPS in plaintext here. For end-to-end EK
confidentiality see token_auth_ek_rsa2048.py.
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

    # 3. RUN THE FLOW
    iotaccesstoken, iotid = cloud.do_device_login(
        credentials.cloudflaretokens, credentials.iotusername, credentials.iotpassword)

    # Step 1: ask the cloud for a challenge word (EK variant)
    cw, transactionid = cloud.do_device_tokenauthEK_requestcw(
        credentials.cloudflaretokens, iotaccesstoken, tid)

    # Step 2: the token returns both the response AND its derived key
    rw, ek = token.do_token_auth_ek(token.hex_to_bytes(cw))

    # Step 3: hand the response back
    transactionidresponse = cloud.do_device_tokenauthEK_replyrw(
        credentials.cloudflaretokens, iotaccesstoken, tid, cw, rw, transactionid)

    # Step 4: poll until the cloud returns its own derivation of the key
    authenticationresult, claimid, ekresult = cloud.do_device_tokenauthEK_checkstatus(
        credentials.cloudflaretokens, iotaccesstoken, transactionid)

    # 4. ┌─ YOUR INTEGRATION POINT ──────────────────────────────────────┐
    #    │ `ek` is your session key. It must equal `ekresult`; if it     │
    #    │ does not, do not use it -- the two sides disagree.            │
    #    └───────────────────────────────────────────────────────────────┘
    print("EK token:     " + ek)
    print("EK CyberRock: " + ekresult + "\n")


if __name__ == "__main__":
    main()
