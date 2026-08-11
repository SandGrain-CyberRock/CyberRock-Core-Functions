"""
Bind several data items to one verification -- cloud issues the starting challenge.

WHEN TO USE   You have a set of values that must be proven together and in
              order -- a batch of sensor readings, a sequence of log records,
              a manifest. Chaining them yields a single value that covers all
              of them, so one verification replaces N.
YOU NEED      A connected token, IoT device credentials, network access.
THIS PROVES   Every item in `l_data` passed through this token, in this
              order. Altering, reordering or dropping any item changes the
              final value.
COST          4 cloud calls (the last one polls), 4 token transfers.

The chain: HCW(n+1) = HRW(n) || data[n]. The token is invoked once per item,
plus once for the initial challenge.
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
    print(tid)

    # 3. RUN THE FLOW
    # The chain needs one more TID than it has data items.
    # Replace l_data with your own 32-hex-char values.
    l_tid = [tid]*3
    l_data = ['ffffffffffffffffffffffffffffff01', 'ffffffffffffffffffffffffffffff02']

    iotaccesstoken, iotid = cloud.do_device_login(
        credentials.cloudflaretokens, credentials.iotusername, credentials.iotpassword)

    # Step 1: the cloud supplies the starting challenge
    cw, transactionid = cloud.do_device_requestDaisyChainCW(
        credentials.cloudflaretokens, iotaccesstoken, l_tid, l_data, False)

    # Step 2: walk the chain -- each item folds into the running value
    hrw = token.do_host_auth(token.hex_to_bytes(cw))

    for d in l_data:

        hcw = hrw + d
        hrw = token.do_host_auth(token.hex_to_bytes(hcw))

    # Step 3: submit the final value
    transactionidresponse = cloud.do_device_replyDaisyChainRW(
        credentials.cloudflaretokens, iotaccesstoken,
        l_tid, l_data, cw, hrw, transactionid, False)

    # Step 4: poll for the verdict
    authenticationresult = cloud.do_device_checkRequestDaisyChainStatus(
        credentials.cloudflaretokens, iotaccesstoken, transactionid, False)

    # 4. ┌─ YOUR INTEGRATION POINT ──────────────────────────────────────┐
    #    │ A pass means the whole batch is intact and in order.          │
    #    └───────────────────────────────────────────────────────────────┘
    print(authenticationresult + '\n')


if __name__ == "__main__":
    main()
