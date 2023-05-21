import logging
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import \
    padding as asymmetric_padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (load_pem_private_key,
                                                          load_pem_public_key)

logger = logging.getLogger()
logger.setLevel('INFO')


class AsymmetricSystem:
    def __init__(self, settings: dict) -> None:
        """Initialization of a asymmetric encryption system.
        Args:
            settings (dict): settings containing file paths.
        """
        self.settings = settings
        logging.info(' Default settings are loaded(AsymmetricSystem)')

    def generation_asymmetric_keys(self) -> tuple:
        """Generates a key for asymmetric encryption.
        Returns:
            tuple: tuple of keys.
        """
        keys = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        private_key = keys
        public_key = keys.public_key()
        logging.info(' Asymmetric keys successfully generated')
        return private_key, public_key

    def serialization_asymmetric_keys(self, public_key: rsa.RSAPublicKey,
                                      private_key: rsa.RSAPrivateKey,
                                      public_pem: str,
                                      private_pem: str) -> None:
        """Save asymmetric keys in a bit sequence in .txt.
        Args:
            public_key (rsa.RSAPublicKey): asymmetric encryption public key.
            private_key (rsa.RSAPrivateKey): asymmetric encryption private key.
            public_pem (str): path to the file to save public key.
            private_pem (str): path to the file to save private key.
        """     
        private_key_serialized = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_key_serialized = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        try:
            with open(public_pem, 'wb') as f:
                f.write(public_key_serialized)
            logging.info(
                f' Public key successfully saved to file: {public_pem}')
        except OSError as err:
            logging.warning(f' Public key not saved\nError:{err}')
            raise
        try:
            with open(private_pem, 'wb') as f:
                f.write(private_key_serialized)
            logging.info(
                f' Private key successfully saved to file: {private_pem}')
        except OSError as err:
            logging.warning(f' Private key not saved\nError:{err}')
            raise

    def get_public_key(self, public_pem: str) -> rsa.RSAPublicKey:
        """loads a public key from .txt.
        Args:
            public_pem (str): path to the file with the public key.
        Returns:
            rsa.RSAPublicKey: public key.
        """
        try:
            with open(public_pem, 'rb') as f:
                public_key_deserialized = f.read()
            public_key = load_pem_public_key(
                public_key_deserialized)
            logging.info(
                f' Public key successfully read from file: {public_pem}')
        except OSError as err:
            logging.warning(f' Public key has not read\nError:{err}')
            raise
        return public_key

    def get_private_key(self, private_pem: str) -> rsa.RSAPrivateKey:
        """loads a private key from .txt.
        Args:
            private_pem (str): path to the file with the private key.
        Returns:
            rsa.RSAPrivateKey: private key.
        """
        try:
            with open(private_pem, 'rb') as f:
                private_key_deserialized = f.read()
            private_key = load_pem_private_key(
                private_key_deserialized, password=None)
            logging.info(
                f' Private key successfully read from file: {private_pem}')
        except OSError as err:
            logging.warning(f' Private key has not read\nError:{err}')
            raise
        return private_key

    def encryption_symmetric_key(self,
                                 public_key: rsa.RSAPublicKey,
                                 symmetric_key: bytes) -> bytes:
        """Encrypts a symmetric key with asymmetric encryption.
        Args:
            public_key (rsa.RSAPublicKey): asymmetric encryption public key.
            symmetric_key (bytes): symmetric encryption key.
        Returns:
            bytes: encrypted symmetric key.
        """
        encrypted_symmetric_key = public_key.encrypt(
            symmetric_key,
            asymmetric_padding.OAEP(
                mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted_symmetric_key

    def decryption_symmetric_key(self,
                                 private_key: rsa.RSAPrivateKey,
                                 encrypted_symmetric_key: bytes) -> bytes:
        """Decrypts a symmetric key with asymmetric encryption.
        Args:
            private_key (rsa.RSAPrivateKey): asymmetric encryption private key.
            encrypted_symmetric_key (bytes): encrypted symmetric key.
        Returns:
            bytes: decrypted symmetric key.
        """
        symmetric_key = private_key.decrypt(
            encrypted_symmetric_key,
            asymmetric_padding.OAEP(
                mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return symmetric_key
    