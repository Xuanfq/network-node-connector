import paramiko
import paramiko.common
import os
import pam
import gnupg
import base64
import logging


class Authenticator:
    def authenticate(self, *args, **kwargs):
        return False


class ServerSessionHandler:
    def handle(self, socket, addr):
        return True, socket


class SSHAuthenticator(Authenticator):
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
        for filename_username in os.listdir(self.authorized_keys_dir):
            file_path = os.path.join(self.authorized_keys_dir, filename_username)
            try:
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


class SSHServerSessionHandler(ServerSessionHandler):

    class SSHAuthenticationServer(paramiko.ServerInterface):
        def __init__(self, authenticator: Authenticator):
            self.authenticator = authenticator

        def check_channel_request(self, kind: str, chanid: int):
            if kind == "session":
                return paramiko.OPEN_SUCCEEDED
            return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

        def check_auth_password(self, username: str, password: str):
            return (
                paramiko.common.AUTH_SUCCESSFUL
                if self.authenticator.authenticate(username=username, password=password)
                else paramiko.common.AUTH_FAILED
            )

        def check_auth_publickey(self, username: str, key):
            return (
                paramiko.common.AUTH_SUCCESSFUL
                if self.authenticator.authenticate(username=username, key=key)
                else paramiko.common.AUTH_FAILED
            )

    def __init__(self, authenticator: Authenticator) -> None:
        self.authenticator = authenticator

    def handle(self, socket, addr):
        transport = paramiko.Transport(socket)
        transport.add_server_key(paramiko.RSAKey.generate(2048))
        server = SSHServerSessionHandler.SSHAuthenticationServer(self.authenticator)
        transport.start_server(server=server)

        channel = transport.accept(20)
        if channel is None:
            logging.warning(f"Authentication failed for {addr}")
            return False, transport

        if transport.is_authenticated():
            logging.info(f"Authentication successful for {addr}")
            return True, channel
        logging.warning(f"Authentication failed for {addr}")
        return False, transport
