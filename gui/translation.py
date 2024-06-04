from enum import Enum

class Translation(Enum):
    TITLE = "File Encryption/Decryption Tool"
    ENCRYPT = "Encrypt"
    DECRYPT = "Decrypt"
    BROWSE = "Browse"
    BACK = "Back"
    COPY_KEY = "Copy Key"
    KEY_COPIED = "Encryption key copied to clipboard"
    ENTER_DECRYPT_KEY = "Enter Decryption Key:"
    ENTER_NEW_NAME = "Enter New File Name:"
    SELECT_FILE_ENCRYPT = "Select File to Encrypt:"
    SELECT_FILE_DECRYPT = "Select File to Decrypt:"
    ERROR_FILE_NAME = "Please provide the file and new file name."
    ERROR_FILE_NAME_KEY = "Please provide the file, decryption key, and new file name."
    ERROR_INVALID_FORMAT = "Invalid key format."
    SUCCESS_ENCRYPT = "File decrypted successfully."