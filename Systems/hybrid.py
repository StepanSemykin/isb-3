import json
import logging
import asymmetric
import symmetric

logger = logging.getLogger()
logger.setLevel('INFO')


class HybridSystem:
    def __init__(self, path_json: str) -> None:
        try:
            with open(path_json) as f:
                self.settings = json.load(f)
            logging.info(' Default settings are loaded')
        except OSError as err:
            logging.warning(
                f' Default settings are not loaded\nError:{err}')
            raise
        try:
            self.symmetric_sys = symmetric.SymmetricSystem(self.settings)
            self.asymmetric_sys = asymmetric.AsymmetricSystem(self.settings)
        except Exception as err:
            raise

    def generation_keys(self) -> None:
        symmetric_key = self.symmetric_sys.generation_symmetric_key()
        private_key, public_key = self.asymmetric_sys.generation_asymmetric_keys()
        encrypted_symmetric_key = self.asymmetric_sys.encryption_symmetric_key(public_key, symmetric_key)
        self.asymmetric_sys.serialization_asymmetric_keys(
            public_key, private_key,
            self.settings['public_key'], self.settings['private_key'])
        self.symmetric_sys.serealization_symmetric_key(
            encrypted_symmetric_key, self.settings['symmetric_key'])
        logging.info(' All keys have been successfully generated and saved')

    def encryption_message(self) -> None:
        private_key = self.asymmetric_sys.get_private_key(self.settings['private_key'])
        encrypted_symmetric_key = self.symmetric_sys.get_symmetric_key(self.settings['symmetric_key'])
        symmetric_key = self.asymmetric_sys.decryption_symmetric_key(private_key, encrypted_symmetric_key)
        self.symmetric_sys.symmetric_encryption(symmetric_key, self.settings['initial_file'], self.settings['encrypted_text'])

    def decryption_message(self) -> None:
        private_key = self.asymmetric_sys.get_private_key(self.settings['private_key'])
        encrypted_symmetric_key = self.symmetric_sys.get_symmetric_key(self.settings['symmetric_key'])
        symmetric_key = self.asymmetric_sys.decryption_symmetric_key(private_key, encrypted_symmetric_key)
        self.symmetric_sys.symmetric_decryption(symmetric_key, self.settings['encrypted_text'], self.settings['decrypted_text'])    

if __name__ == "__main__":
    a = HybridSystem("D:\\lab_oib\\isb-3\\Files\\settings.json")
    a.generation_keys()
    a.encryption_message()
    a.decryption_message()
    
