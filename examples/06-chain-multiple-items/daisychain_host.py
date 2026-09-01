"""
Bind several data items to one verification -- device issues the starting challenge.

WHEN TO USE   As daisychain.py, but the device chooses when to start and
              supplies its own ChainCW -- so the chain can be built offline
              and submitted later.
YOU NEED      A connected token, IoT device credentials, network access.
THIS PROVES   Every item in `l_data` passed through this token, in this
              order.
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

    print(tid)

    # 3. RUN THE FLOW
    # NOTE: make_challenge() has one-second granularity. See docs/known-issues.md.
    hcw = token.make_challenge()

    l_tid = [tid, tid, tid]

    l_data = ['ffffffffffffffffffffffffffffff01', 'ffffffffffffffffffffffffffffff02']

    iotaccesstoken, iotid = cloud.do_device_login(
        credentials.cloudflaretokens, credentials.iotusername, credentials.iotpassword)

    hrw = token.do_host_auth(token.hex_to_bytes(hcw))

    hrw_n = hrw

    for d in l_data:

        hcw_n = hrw_n + d
        hrw_n = token.do_host_auth(token.hex_to_bytes(hcw_n))

    transactionid = cloud.do_device_HostDaisyChainAuthentication(
        credentials.cloudflaretokens, iotaccesstoken,
        l_tid, l_data, hcw, hrw_n, False)

    authenticationresult = cloud.do_device_checkRequestHostDaisyChainAuthenticationStatus(
        credentials.cloudflaretokens, iotaccesstoken, transactionid, False)

    # 4. ┌─ YOUR INTEGRATION POINT ──────────────────────────────────────┐
    #    │ A pass means the whole batch is intact and in order.          │
    #    └───────────────────────────────────────────────────────────────┘
    print(authenticationresult + '\n')


if __name__ == "__main__":
    main()
