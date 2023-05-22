import sys
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import (QApplication, QFileDialog, QLabel, QMainWindow,
                             QMessageBox, QPushButton, QWidget)
import hybrid

SETTINGS = 'Files\\settings.json'


class GraphicalInterface(QMainWindow):
    def __init__(self) -> None:
        """Initialization of the application window.
        """
        super(GraphicalInterface, self).__init__()
        self.settings_not_loaded = True
        self.setWindowTitle('CryptoSystem')
        self.setFixedSize(300, 300)
        self.move(700, 200)
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.intro = QLabel(
            'Вас приветствует криптосистема, позволяющая шифровать \
                сообщения с использованием алгоритмов RSA и SEED',
            self.central_widget)
        self.intro.setFont(QFont('Arial', 12))
        self.intro.setGeometry(50, -90, 200, 300)
        self.intro.setWordWrap(True)
        self.intro.setAlignment(Qt.AlignCenter)
        self.settings_file_label = QLabel(
            'SETTINGS FILE:', self.central_widget)
        self.settings_file_label.setGeometry(10, 145, 100, 30)
        self.load_settings_button = QPushButton(
            'LOAD', self.central_widget)
        self.load_settings_button.setToolTip('Сhanges the default settings')
        self.load_settings_button.clicked.connect(self.upload_settings_file)
        self.load_settings_button.setGeometry(190, 145, 100, 30)
        self.enc_message = QLabel('TEXT ENCRYPTION:', self.central_widget)
        self.enc_message.setGeometry(10, 200, 100, 30)
        self.encryption_button = QPushButton('ENCRYPTION', self.central_widget)
        self.encryption_button.setGeometry(190, 200, 100, 30)
        self.encryption_button.clicked.connect(self.perform_text_encoding)
        self.dec_message = QLabel('TEXT DECRYPTION:', self.central_widget)
        self.dec_message.setGeometry(10, 255, 100, 30)
        self.decryption_button = QPushButton('DECRYPTION', self.central_widget)
        self.decryption_button.setGeometry(190, 255, 100, 30)
        self.decryption_button.clicked.connect(self.perform_text_decoding)

    def upload_settings_file(self) -> None:
        """loads the settings/default settings for 
        the cryptosystem and generates keys.
        """
        try:
            file_name, _ = QFileDialog.getOpenFileName(
                self, 'Open Settings File', '', 'Settings Files (*.json)')
            self.system = hybrid.HybridSystem(file_name)
            QMessageBox.information(
                self, 'Settings',
                f'Settings successfully loaded from file: {file_name}')
        except OSError as err:
            self.system = hybrid.HybridSystem(SETTINGS)
            QMessageBox.information(
                self, 'Settings', f'Settings file was not loaded.'
                f' The default settings are set\nPath: {SETTINGS}')
        self.settings_not_loaded = False
        self.system.generation_keys()

    def perform_text_encoding(self) -> None:
        """Encrypts the message.
        """
        if self.settings_not_loaded == True:
            QMessageBox.information(self, 'Settings',
                                    f'Settings file was not loaded.'
                                    f' Please download the settings')
            self.upload_settings_file()
        try:
            self.system.encryption_message()
        except Exception as err:
            QMessageBox.information(
                self, 'Encryption',
                f'The message is NOT encrypted\n{err.__str__}')
        else:
            QMessageBox.information(self, 'Encryption',
                                    'The message is encrypted')

    def perform_text_decoding(self) -> None:
        """Decrypts the message.
        """
        if self.settings_not_loaded == True:
            QMessageBox.information(self, 'Settings',
                                    f'Settings file was not loaded.'
                                    f' Please download the settings')
            self.upload_settings_file()
        try:
            self.system.decryption_message()
        except Exception as err:
            QMessageBox.information(
                self, 'Decryption',
                f'The message is NOT Decrypted\n{err.__str__}')
        else:
            QMessageBox.information(self, 'Decryption',
                                    'The message is decrypted')


if __name__ == "__main__":
    app = QApplication(sys.argv)
    w = GraphicalInterface()

    w.show()
    sys.exit(app.exec_())
