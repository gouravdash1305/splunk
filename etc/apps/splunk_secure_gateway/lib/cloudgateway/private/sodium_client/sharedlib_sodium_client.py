import sys
import logging


from . import pysodium
from .errors import SodiumOperationError

class SodiumClient(object):
    def __init__(self, logger=None):
        if not logger:
            logger = logging.Logger("sodium_client", level=logging.ERROR)

        self.logger = logger


    def box_generate_keypair(self):
        try:
            return pysodium.crypto_box_keypair()
        except ValueError as v:
            raise SodiumOperationError(str(v))

    def box_seal(self, plaintext, receiver_public_key):
        try:
            return pysodium.crypto_box_seal(plaintext, receiver_public_key)
        except ValueError as v:
            raise SodiumOperationError(str(v))

    def box_seal_open(self, ciphertext, self_public_key, self_secret_key):
        try:
            return pysodium.crypto_box_seal_open(ciphertext, self_public_key, self_secret_key)
        except ValueError as v:
            raise SodiumOperationError(str(v))

    def box_easy(self, plaintext, sender_secret_key, receiver_public_key):
        try:
            nonce = pysodium.randombytes(pysodium.crypto_box_NONCEBYTES)
            ciphertext = pysodium.crypto_box(plaintext, nonce, receiver_public_key, sender_secret_key)
            return ciphertext, nonce
        except ValueError as v:
            raise SodiumOperationError(str(v))

    def box_easy_open(self, ciphertext, nonce, sender_public_key, receiver_secret_key):
        try:
            return pysodium.crypto_box_open(ciphertext, nonce, sender_public_key, receiver_secret_key)
        except ValueError as v:
            raise SodiumOperationError(str(v))

    def sign_generate_keypair(self):
        try:
            return pysodium.crypto_sign_keypair()
        except ValueError as v:
            raise SodiumOperationError(str(v))

    def sign_detached(self, msg, sender_secret_key):
        try:
            return pysodium.crypto_sign_detached(msg, sender_secret_key)
        except ValueError as v:
            raise SodiumOperationError(str(v))

    def sign_detached_verify(self, msg, signature, sender_public_key):
        try:
            pysodium.crypto_sign_verify_detached(signature, msg, sender_public_key)
            return True
        except ValueError as v:
            raise SodiumOperationError(str(v))

    def hash_generic(self, msg):
        state = pysodium.crypto_generichash_init()
        pysodium.crypto_generichash_update(state, msg)
        try:
            hash = pysodium.crypto_generichash_final(state)
            return hash
        except ValueError as v:
            raise SodiumOperationError(str(v))