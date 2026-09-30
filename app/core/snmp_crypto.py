"""
Encryption for NOC SNMP credentials at rest (community string, SNMPv3 keys).

Background polling needs these without a user in the loop, so they are stored
encrypted; see app/core/credential_crypto.py for the key derivation.
"""
from app.core.credential_crypto import PURPOSE_NOC_SNMP, decrypt, encrypt


def encrypt_secret(plaintext: str) -> str:
    return encrypt(plaintext, PURPOSE_NOC_SNMP)


def decrypt_secret(ciphertext: str) -> str:
    return decrypt(ciphertext, PURPOSE_NOC_SNMP)
