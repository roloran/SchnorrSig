# This example does not use the Schnorr library from this repository!
# It is an example for interoperability with other programming languages

import os
import hashlib
import ecdsa

class SchnorrSignature:
    def __init__(self, curve=ecdsa.SECP256k1):
        self.curve = curve
        self.generator = curve.generator
        self.order = self.generator.order()

    def generate_keypair(self):
        private_key = ecdsa.util.randrange(self.order)
        public_key = self.generator * private_key
        return private_key, public_key

    def sign(self, private_key, message):
        # Generate a random nonce
        k = ecdsa.util.randrange(self.order)
        R = self.generator * k

        # Compute the hash
        e = self.hash_function(R, message) % self.order

        # Compute signature s
        s = (e * private_key) % self.order
        s = (k - s) % self.order
        return (R, s)

    def verify(self, public_key, message, signature):
        R, s = signature

        # Compute the hash
        e = self.hash_function(R, message) % self.order

        # Compute signature
        R_prime = self.generator * s
        e_pubkey = public_key * e
        R_prime = R_prime + e_pubkey

        return R_prime.x() == R.x()

    def hash_function(self, R_x, message):
        """ Hash function combining R_x and the message """
        h = hashlib.sha256()
        h.update(R_x.to_bytes(encoding='compressed'))
        h.update(message.encode('utf-8'))
        return int.from_bytes(h.digest(), 'big')

    def export_public_key_hex(self, key):
        """ Export a key (private or public) as a hexadecimal string """
        return key.to_bytes(encoding='compressed').hex()

    def export_private_key_hex(self, key):
        """ Export a key (private or public) as a hexadecimal string """
        return key.to_bytes(32, 'big').hex()

    def import_public_key_hex(self, hex_key):
        """ Import a key (private or public) from a hexadecimal string """
        return ecdsa.ellipticcurve.PointJacobi.from_bytes(self.curve.curve, bytes.fromhex(hex_key))

    def import_private_key_hex(self, hex_key):
        """ Import a key (private or public) from a hexadecimal string """
        return int(hex_key, 16)

    def export_signature_hex(self, signature):
        """ Export a signature as a hexadecimal string """
        R, s = signature
        R_bytes = R.to_bytes(encoding='compressed')
        s_bytes = s.to_bytes(32, 'big')
        return R_bytes.hex() + ":" + s_bytes.hex()

    def import_signature_hex(self, hex_signature):
        """ Import a signature from a hexadecimal string """
        R_hex, s_hex = hex_signature.split(":")
        R = ecdsa.ellipticcurve.PointJacobi.from_bytes(self.curve.curve, bytes.fromhex(R_hex))
        s = int(s_hex, 16)
        return (R, s)


# Usage
if __name__ == "__main__":
    schnorr = SchnorrSignature()

    print("Signature example start")
    private_key, public_key = schnorr.generate_keypair()
    message = "Hello World!"
    signature = schnorr.sign(private_key, message)
    verification = schnorr.verify(public_key, message, signature)
    print("Signature verification:", verification)

    print("\nExported keys and signature")
    private_key_string = schnorr.export_private_key_hex(private_key)
    print("Private key export:", private_key_string)
    public_key_string = schnorr.export_public_key_hex(public_key)
    print("Public key export:", public_key_string)
    signature_string = schnorr.export_signature_hex(signature)
    print("Hex-encoded signature string:", signature_string)

    print("\nImported keys and signature")
    private_key = schnorr.import_private_key_hex(private_key_string)
    public_key = schnorr.import_public_key_hex(public_key_string)
    signature = schnorr.import_signature_hex(signature_string)
    verification = schnorr.verify(public_key, message, signature)
    print("Signature verification:", verification)


    print("\nImported signature from Arduino")
    public_key = schnorr.import_public_key_hex("02321073057379812CBDE5A570722F6F40A862A983D6396E694EF8B1C11B0A1EA4")
    signature = schnorr.import_signature_hex("0355819FED2AB00C533542E2BF05750DE24BB1B70831E29D70BB5ADF1DA5092DAF:E130959FAC266D35B3C7D4DE1466541B25CECF4F950AAB98390216BCC4A0D471")
    verification = schnorr.verify(public_key, "Hello World!", signature)
    print("Signature verification:", verification)

    print("Signature example end")

