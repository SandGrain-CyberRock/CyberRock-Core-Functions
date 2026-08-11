"""
Bind several data items to one verification -- device issues the starting challenge.

WHEN TO USE   As daisychain.py, but the device chooses when to start and
              supplies its own ChainCW -- so the chain can be built offline
              and submitted later.
YOU NEED      A connected token, IoT device credentials, network access.
THIS PROVES   Every item in `l_data` passed through this token, in this
              order.
COST          3 cloud calls (the last one polls), 3 token transfers.

!! READ THIS BEFORE COPYING !!
This example carries two known defects, preserved deliberately so its
behaviour matches the pre-restructure original. Both are marked inline and
documented in docs/known-issues.md:
  1. the generated ChainCW is overwritten by a hardcoded constant;
  2. the chain loop does not advance -- it works only because l_data has
     exactly one item. With two or more, the submitted value is WRONG.
For a correct chain loop, see daisychain.py or daisychain_hrw.py.
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
    # NOTE: the line below discards the generated challenge and replaces it
    # with a fixed constant, making the call above dead. Preserved verbatim
    # during the restructure. See docs/known-issues.md.
    hcw = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
    print(hcw)

    l_tid = [tid]*2

    l_data = ['ffffffffffffffffffffffffffffff01']

    iotaccesstoken, iotid = cloud.do_device_login(
        credentials.cloudflaretokens, credentials.iotusername, credentials.iotpassword)

    hrw = token.do_host_auth(token.hex_to_bytes(hcw))
    print(hrw)

    # NOTE: this loop reads `hrw` but never reassigns it, so the chain does
    # not advance past the first link. Correct today only because l_data has
    # exactly one item. Preserved verbatim. See docs/known-issues.md.
    for d in l_data:

        hcw_n = hrw + d
        hrw_n = token.do_host_auth(token.hex_to_bytes(hcw_n))

    transactionid = cloud.do_device_HostDaisyChainAuthentication(
        credentials.cloudflaretokens, iotaccesstoken,
        l_tid, l_data, hcw, hrw_n, False)

    authenticationresult = cloud.do_device_checkRequestHostDaisyChainAuthenticationStatus(
        credentials.cloudflaretokens, iotaccesstoken, transactionid, False)

    # 4. ┌─ YOUR INTEGRATION POINT ──────────────────────────────────────┐
    #    │ A pass means the whole batch is intact and in order --        │
    #    │ subject to the loop caveat above.                             │
    #    └───────────────────────────────────────────────────────────────┘
    print(authenticationresult + '\n')


if __name__ == "__main__":
    main()
