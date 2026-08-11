"""
Tag data AND derive a session key -- immediate result, key arrives encrypted.

WHEN TO USE   The strongest and quickest variant in this folder: one
              round-trip returning both the tag and a key that is never
              readable in transit, even to a terminating proxy.
YOU NEED      A connected token, IoT device credentials, network access,
              and `pip install cryptography`.
THIS PROVES   The cloud derived the same HRW, and the EK decrypted with the
              client's private key matches the hardware-derived one.
COST          2 cloud calls, 2 token transfers, plus a local RSA-2048
              keygen (~0.1-1s).

Envelope format is hybrid-crypto-js: an AES-CBC ciphertext plus the AES key
wrapped with RSA-OAEP.
"""

import sys
import json
import base64
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import CyberRock_Cloud as cloud
import CyberRock_Token as token
import CyberRock_Config as config
import SandGrain_Credentials as credentials


def generate_rsa_keypair():
    """Fresh RSA-2048 keypair. The public half goes to the cloud as PEM."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode('utf-8')
    return private_key, public_key_pem


def decrypt_hybrid_ek(private_key, encrypted_ek_json_str):
    """Open a hybrid-crypto-js envelope: RSA-OAEP unwraps the AES-CBC key.

    NOTE: SHA-1 in OAEP/MGF1 is required for hybrid-crypto-js interoperability,
    and the PKCS7 padding is stripped without validation.
    See docs/known-issues.md.
    """
    envelope = json.loads(encrypted_ek_json_str)
    iv = base64.b64decode(envelope['iv'])[:16]
    cipher_text = base64.b64decode(envelope['cipher'])
    encrypted_aes_key = base64.b64decode(list(envelope['keys'].values())[0])

    aes_key = private_key.decrypt(encrypted_aes_key, asym_padding.OAEP(
        mgf=asym_padding.MGF1(algorithm=hashes.SHA1()),
        algorithm=hashes.SHA1(), label=None))

    decryptor = Cipher(algorithms.AES(aes_key), modes.CBC(iv)).decryptor()
    padded = decryptor.update(cipher_text) + decryptor.finalize()
    return padded[:-padded[-1]].decode('utf-8')


def main():

    # 1. CONFIGURE -- interface (SPI/USB) and environment come from CyberRock_Config
    config.init()

    # Generate the keypair the cloud will encrypt the EK to
    print("[*] Generating RSA-2048 keypair...")
    private_key, public_key_pem = generate_rsa_keypair()

    # 2. CONNECT -- read the token's identity
    tid = token.get_tid()
    print(f"[*] TID: {tid}")

    # 3. RUN THE FLOW
    # Substitute your own 64-hex-char value here to tag real data.
    # NOTE: make_challenge() has one-second granularity. See docs/known-issues.md.
    hcw = token.make_challenge()

    # The token returns both the tag AND its derived key
    hrw_token, ek_token = token.do_host_auth_ek(token.hex_to_bytes(hcw))
    print(f"[*] HRW (token): {hrw_token}")
    print(f"[*] EK  (token): {ek_token}")

    iotaccesstoken, iotid = cloud.do_device_login(
        credentials.cloudflaretokens, credentials.iotusername, credentials.iotpassword, False)

    # Ask the cloud for the tag + wrapped key (priority / synchronous)
    result, hrw_cloud, encrypted_ek = cloud.do_device_EKpriorityrequestHRW_rsa(
        credentials.cloudflaretokens, iotaccesstoken, tid, hcw, public_key_pem, False)

    print(f"\n[*] Status: {result}")
    print(f"[*] HRW (cloud): {hrw_cloud}")

    # Unwrap locally
    ek_decrypted = decrypt_hybrid_ek(private_key, encrypted_ek)
    print(f"[*] EK (decrypted): {ek_decrypted}")

    # 4. ┌─ YOUR INTEGRATION POINT ──────────────────────────────────────┐
    #    │ BOTH must match before you trust either value.                │
    #    └───────────────────────────────────────────────────────────────┘
    if hrw_token == hrw_cloud and ek_token == ek_decrypted:
        print("\n[OK] HRW and EK match — RSA-encrypted delivery successful")
    else:
        print("\n[!] Mismatch!")


if __name__ == "__main__":
    main()
