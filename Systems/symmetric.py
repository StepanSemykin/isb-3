import os
import logging
from cryptography.hazmat.primitives import padding as symmetric_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

logger = logging.getLogger()
logger.setLevel('INFO')


class SymmetricSystem:
    def __init__(self, settings: dict) -> None:
        """Initialization of a symmetric encryption system.
        Args:
            settings (dict): settings containing file paths.
        """
        self.settings = settings
        logging.info(' Default settings are loaded(SymmetricSystem)')

    def generation_symmetric_key(self) -> bytes:
        """Generates a key for symmetric encryption.
        Returns:
            bytes: symmetric encryption key.
        """
        symmetric_key = os.urandom(16)
        logging.info(' Symmetric key(128 bits) successfully generated')
        return symmetric_key

    def serealization_symmetric_key(self, key: bytes, path: str) -> None:
        """Save symmetric key in a bit sequence in .txt.
        Args:
            key (bytes): symmetric key.
            path (str): path to the file to save the key.
        """
        try:
            with open(path, 'wb') as f:
                f.write(key)
            logging.info(f' Symmetric key successfully saved to file: {path}')
        except OSError as err:
            logging.warning(f' Symmetric key not saved\nError: {err}')
            raise

    def get_symmetric_key(self, path: str) -> bytes:
        """loads a symmetric key from .txt.
        Args:
            path (str): path to the symmetric key file.
        Returns:
            bytes: symmetric key.
        """
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
        """Encrypts text using a symmetric algorithm.
        Args:
            key (bytes): symmetric key.
            path_message (str): path to the source text file.
            path_encrypted_message (str): path to the encrypted text file.
        """
        try:
            with open(path_message, 'rb') as f:
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
            with open(path_encrypted_message, 'wb') as f:
                f.write(encrypted_data)
            logging.info(
                f' Encrypted message write to file: {path_encrypted_message}')
        except OSError as err:
            logging.warning(f' Encrypted message was not write\nError:{err}')
            raise

    def symmetric_decryption(self, key: bytes,
                             path_encrypted_message: str,
                             path_decrypted_message: str) -> None:
        """Decrypts the text using a symmetric algorithm.
        Args:
            key (bytes): symmetric key.
            path_encrypted_message (str): path to the encrypted file.
            path_decrypted_message (str): path to the decrypted file.
        """
        try:
            with open(path_encrypted_message, 'rb') as f:
                message = f.read()
            logging.info(
                f' Encrypted message read from file: {path_encrypted_message}')
        except OSError as err:
            logging.warning(f' Encrypted message has not read\nError:{err}')
            raise
        iv = message[:16]
        message = message[16:]
        cipher = Cipher(algorithms.SEED(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        data = decryptor.update(message) + decryptor.finalize()
        unpadder = symmetric_padding.PKCS7(128).unpadder()
        decrypted_data = unpadder.update(data) + unpadder.finalize()
        try:
            with open(path_decrypted_message, 'wb') as f:
                f.write(decrypted_data)
            logging.info(
                f' Decrypted message write to file: {path_decrypted_message}')
        except OSError as err:
            logging.warning(f' Decrypted message was not write\nError:{err}')
            raise
