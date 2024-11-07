import paramiko
import paramiko.common
import os
import pam
import gnupg
import base64
import logging


class SSHAuthenticator:
    def __init__(self, authorized_keys_dir: str = None, strict_mode: bool = True):
        self.authorized_keys_dir: str = authorized_keys_dir
        self.strict_mode: bool = strict_mode
        self.authorized_keys: dict[str, tuple[any, list[str], str]] = {}
        self.pam = pam.pam()
        self.load_authorized_keys()

    def load_authorized_keys(self):
        """Load authorized public keys from all files in the authorized_keys directory."""
        if not self.authorized_keys_dir or not os.path.exists(self.authorized_keys_dir):
            logging.warning("Authorized keys directory not found or invalid.")
            print(self.authorized_keys_dir, os.path.exists(self.authorized_keys_dir))
            return {}

        authorized_keys = {}
        try:
            for filename_username in os.listdir(self.authorized_keys_dir):
                file_path = os.path.join(self.authorized_keys_dir, filename_username)
                if os.path.isfile(file_path):
                    with open(file_path, "r") as f:
                        for line in f:
                            parts = line.strip().split()
                            if len(parts) >= 2:
                                key_type = parts[0]
                                key_data = parts[1]
                                options = parts[2:] if len(parts) > 2 else []
                                key = paramiko.RSAKey(data=base64.b64decode(key_data))
                                authorized_keys[key_data] = (
                                    key,
                                    options,
                                    filename_username,
                                )
        except Exception as e:
            logging.error(f"Error loading authorized keys: {file_path} -> {e}")
        self.authorized_keys = authorized_keys
        return authorized_keys

    def check_password(self, username, password):
        """Check if the provided username and password are valid using PAM."""
        try:
            result = self.pam.authenticate(username, password, service="sshd")
            if result:
                logging.info(f"Password authentication successful for user {username}")
            else:
                logging.warning(f"Password authentication failed for user {username}")
            return result
        except Exception as e:
            logging.error(f"Error during PAM authentication: {e}")
            return False

    def check_public_key(self, username, key):
        """Check if the provided public key is authorized for the given username."""
        key_data = key.get_base64()
        if key_data in self.authorized_keys:
            if self.strict_mode:
                key, options, key_username = self.authorized_keys[key_data]
                if username == key_username:
                    return True
                if username in [
                    item.split("@", 1)[0]
                    for item in options
                    if len(item.split("@", 1)) > 1
                ]:
                    return True
                logging.warning(f"Public key authentication failed for user {username}")
                return False
            logging.info(f"Public key authentication successful for user {username}")
            return True
        else:
            logging.warning(f"Public key authentication failed for user {username}")
            return False

    def authenticate(self, username, password=None, key=None):
        """Authenticate the user based on password, public key, or GPG signature."""
        if password and self.check_password(username, password):
            return True
        if key and self.check_public_key(username, key):
            return True
        logging.warning(f"Authentication failed for user {username}")
        return False
