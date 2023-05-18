import os
import logging
from cryptography.hazmat.primitives import padding as symmetric_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class SymmetricSystem:
    def __init__(self):
        pass

    def generation_key(self) -> bytes:
        symmetric_key = os.urandom(16)
        logging.info('Symmetric key(128 bits) successfully generated')
        return symmetric_key
    
    def serealization_key(self, key: bytes, path: str) -> None:
        try:
            with open(path, 'wb') as f:
                f.write(key)
            logging.info(f' Symmetric key successfully saved to file: {path}')
        except OSError as err:
            logging.warning(f' Symmetric key not saved\nError: {err}')
            raise

    def get_symmetric_key(self, path: str) -> bytes:
        try:
            with open(path, 'rb') as f:
                key = f.read()
            logging.info(f' Symmetric key successfully read from file: {path}')
        except OSError as err:
            logging.warning(f' Symmetric key has not read\nError:{err}')
            raise
        return key
    
    def symmetric_encryption(self, key: bytes, path_message: str, 
                             path_encrypted_message: str) -> None:
        try:
            with open(path_message, 'r') as f:
                message = f.read()
            logging.info(f' Message read from file: {path_message}')
        except OSError as err:
            logging.warning(f' Message has not read\nError:{err}')
            raise
        padder = symmetric_padding.PKCS7(128).padder()
        padded_text = padder.update(message) + padder.finalize()
        iv = os.urandom(16)
        cipher = Cipher(algorithms.SEED(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_text) + encryptor.finalize()
        encrypted_data = iv + encrypted_data
        try:
            with open(path_encrypted_message, 'w') as f:
                f.write(encrypted_data)
            logging.info(f' Message read from file: {path_message}')
        except OSError as err:
            logging.warning(f' Message has not read\nError:{err}')
            raise