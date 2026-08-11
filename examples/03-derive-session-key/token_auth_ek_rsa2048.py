"""
Derive a shared session key (EK) -- cloud issues the challenge, EK arrives encrypted.

WHEN TO USE   When HTTPS alone is not enough -- a terminating proxy, a
              corporate TLS-inspection middlebox, or a compliance rule that
              forbids key material being readable at any hop. The client
              generates an RSA-2048 keypair per run and only it can open
              the returned key.
YOU NEED      A connected token, IoT device credentials, network access,
              and `pip install cryptography`.
THIS PROVES   The EK decrypted with the client's private key matches the
              one the token derived in hardware.
COST          4 cloud calls (the last one polls), 2 token transfers,
              plus a local RSA-2048 keygen (~0.1-1s).

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

    # NOTE: the next two lines are a dead first pass -- they build two separate
    # decryptor objects and the result is discarded and recomputed below.
    # Preserved verbatim during the restructure. See docs/known-issues.md.
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    padded = cipher.decryptor().update(cipher_text) + cipher.decryptor().finalize()
    # Re-do decryption in one pass
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
    iotaccesstoken, iotid = cloud.do_device_login(
        credentials.cloudflaretokens, credentials.iotusername, credentials.iotpassword, False)

    # Step 1: request CW, handing over the public key
    cw, transactionid = cloud.do_device_tokenauthEK_requestcw_rsa(
        credentials.cloudflaretokens, iotaccesstoken, tid, public_key_pem, False, False)

    # Step 2: the token returns both the response AND its derived key
    rw, ek_token = token.do_token_auth_ek(token.hex_to_bytes(cw))

    # Step 3: hand the response back
    cloud.do_device_tokenauthEK_replyrw(
        credentials.cloudflaretokens, iotaccesstoken, tid, cw, rw, transactionid, False, False)

    # Step 4: poll for the verdict and the wrapped key
    authenticationresult, claimid, encrypted_ek = cloud.do_device_tokenauthEK_checkstatus_rsa(
        credentials.cloudflaretokens, iotaccesstoken, transactionid, False, False)

    print(f"[*] Auth result: {authenticationresult}")

    # Step 5: unwrap locally
    ek_decrypted = decrypt_hybrid_ek(private_key, encrypted_ek)

    print(f"[*] EK (token):     {ek_token}")
    print(f"[*] EK (decrypted): {ek_decrypted}")

    # 4. ┌─ YOUR INTEGRATION POINT ──────────────────────────────────────┐
    #    │ Use `ek_decrypted` as your session key only once it matches   │
    #    │ the hardware-derived `ek_token`.                              │
    #    └───────────────────────────────────────────────────────────────┘
    if ek_token == ek_decrypted:
        print("\n[OK] Ephemeral Keys match — RSA-encrypted delivery successful")
    else:
        print("\n[!] Ephemeral Key mismatch!")


if __name__ == "__main__":
    main()
