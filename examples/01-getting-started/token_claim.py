"""
Bind a token to your tenant account (claiming).

WHEN TO USE   Once per token, during provisioning. An unclaimed token
              authenticates with status CLAIM_TOKEN instead of AUTH_OK;
              claiming is what turns it into a device you own.
YOU NEED      A connected token, IoT device credentials, AND tenant
              credentials (tenantusername / tenantpassword).
THIS PROVES   The token is now bound to your tenant -- re-authenticating
              afterwards returns AUTH_OK.
COST          Up to 9 cloud calls, 2-3 token transfers
              (2 if already claimed, 3 on the claiming path).
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import CyberRock_Cloud as cloud
import CyberRock_Token as token
import CyberRock_Config as config
import SandGrain_Credentials as credentials


def do_token_authentication(iotaccesstoken, tid):
    """Perform a full 3-step token authentication. Returns (status, claimid)."""
    cw, transactionid = cloud.do_device_tokenauth_requestcw(
        credentials.cloudflaretokens, iotaccesstoken, tid, False, False)

    rw = token.do_token_auth(token.hex_to_bytes(cw))

    cloud.do_device_tokenauth_replyrw(
        credentials.cloudflaretokens, iotaccesstoken, tid, cw, rw, transactionid, False, False)

    authenticationresult, claimid = cloud.do_device_tokenauth_checkstatus(
        credentials.cloudflaretokens, iotaccesstoken, transactionid, False, False)

    return authenticationresult, claimid


def main():

    # 1. CONFIGURE -- interface (SPI/USB) and environment come from CyberRock_Config
    config.init()

    # 2. CONNECT -- read the token's identity
    tid = token.get_tid()
    print(f"TID: {tid}")

    # 3. RUN THE FLOW
    # Step 1: Device login
    iotaccesstoken, iotid = cloud.do_device_login(
        credentials.cloudflaretokens, credentials.iotusername, credentials.iotpassword, False)

    # Step 2: Token authentication -- tells us whether claiming is needed
    print("\n--- Initial Token Authentication ---")
    authenticationresult, claimid = do_token_authentication(iotaccesstoken, tid)
    print(f"Auth result: {authenticationresult}")

    # Step 3: Check if token needs claiming
    if authenticationresult == 'AUTH_OK':
        print("Token is already claimed — no action needed")
        return

    if authenticationresult != 'CLAIM_TOKEN':
        print(f"Authentication failed with status: {authenticationresult}")
        return

    # Step 4: Token needs claiming — log in as tenant
    print(f"\nClaim Token ID: {claimid}")
    print("Logging in as tenant...")

    tenantaccesstoken = cloud.do_tenant_login(
        credentials.cloudflaretokens, credentials.tenantusername, credentials.tenantpassword, False)

    # Step 5: Claim the token
    result = cloud.do_tenant_claimtoken(
        credentials.cloudflaretokens, tenantaccesstoken, claimid, False)

    print(f"Claim result: {result}")

    if not result:
        print("Token claim failed!")
        return

    print("Token claimed successfully")

    # Step 6: Re-authenticate to confirm the claim took effect
    print("\n--- Post-Claim Token Authentication ---")
    authenticationresult2, _ = do_token_authentication(iotaccesstoken, tid)
    print(f"Auth result: {authenticationresult2}")

    # 4. ┌─ YOUR INTEGRATION POINT ──────────────────────────────────────┐
    #    │ AUTH_OK here means the token is bound to your tenant and      │
    #    │ ready for the flows in 02-prove-device-identity/.             │
    #    └───────────────────────────────────────────────────────────────┘
    if authenticationresult2 == 'AUTH_OK':
        print("Token authentication confirmed after claiming")
    else:
        print(f"Unexpected post-claim status: {authenticationresult2}")


if __name__ == "__main__":
    main()
