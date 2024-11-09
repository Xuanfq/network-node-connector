import paramiko
import paramiko.common
import os
import pam
import base64
import logging
import hashlib


class Authenticator:
    def authenticate(self, *args, **kwargs):
        return False


class ServerSessionHandler:
    def handle(self, socket, addr):
        return True, socket


class PasswordEncryptor:

    def encrypte(
        self,
        password,
        hash="sha256",
        salt=None,
        salt_before=False,
        auto_salt=False,
        auto_salt_size=16,
    ):
        if auto_salt or salt:
            if not salt:
                salt = os.urandom(auto_salt_size)
            elif type(salt) == str:
                salt = salt.encode()
            password_plus = str(password).encode() + salt
            if salt_before:
                password_plus = salt + str(password).encode()
        else:
            password_plus = str(password).encode()
        if hash == "sha256":
            hashed_password = hashlib.sha256(password_plus).hexdigest()
        elif hash == "sha384":
            hashed_password = hashlib.sha384(password_plus).hexdigest()
        elif hash == "sha512":
            hashed_password = hashlib.sha512(password_plus).hexdigest()
        else:
            return password
        if salt:
            return hashed_password, salt
        return hashed_password, None


class SSHAuthenticator(Authenticator):

    def __init__(
        self,
        user_pass_dict: dict[str, any] = {},
        user_pass_allow_local: bool = True,
        user_pass_local_root_only: bool = True,
        authorized_pkeys_dir: str = None,
        strict_mode: bool = True,
    ):
        """SSH Protocol Authenticator

        :param dict[str, any] user_pass_dict:
                username and it's password, it's key and value:

                    - username:password
                    - username:(password_hash,salt,hashtype)

        :param bool user_pass_allow_local:
                allow local pc's user authenticate pass or not

        :param bool user_pass_local_root_only:
                only allow local pc's root user authenticate if allow local pc's user authenticate

        :param str authorized_pkeys_dir:
                directory of authorized public keys. and the files in that dir need to use username to naming

        :param bool strict_mode:
                strict mode open or not

        Return: return_description
        """

        self.user_pass_dict: dict[str, str] = user_pass_dict
        self.user_pass_allow_local = user_pass_allow_local
        self.user_pass_local_root_only = user_pass_local_root_only
        self.authorized_pkeys_dir: str = authorized_pkeys_dir
        self.strict_mode: bool = strict_mode
        self.authorized_keys: dict[str, tuple[any, list[str], str]] = {}
        self.pam = pam.pam()
        self.encryptor = PasswordEncryptor()
        self.load_authorized_keys()

    def load_authorized_keys(self):
        """Load authorized public keys from all files in the authorized_keys directory."""
        authorized_keys = {}
        if not self.authorized_pkeys_dir or not os.path.exists(
            self.authorized_pkeys_dir
        ):
            logging.warning("Authorized keys directory not found or invalid.")
        else:
            for filename_username in os.listdir(self.authorized_pkeys_dir):
                file_path = os.path.join(self.authorized_pkeys_dir, filename_username)
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
            if username in self.user_pass_dict:
                passwd_value = self.user_pass_dict[username]
                if type(passwd_value) == list or type(passwd_value) == tuple:
                    hash_password, hash_salt, hash_type = passwd_value
                    hpassword, hsalt = self.encryptor.encrypte(
                        password=password, salt=hash_salt, hash=hash_type
                    )
                    if hash_password == hpassword:
                        return True
                    return False
                return passwd_value == password
            if self.user_pass_allow_local:
                if self.user_pass_local_root_only and username != "root":
                    return False
                result = self.pam.authenticate(username, password, service="login")
                if result:
                    logging.info(
                        f"Password authentication successful for user {username}"
                    )
                else:
                    logging.warning(
                        f"Password authentication failed for user {username}"
                    )
                return result
            return False
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


class SSHServerSessionAuthHandler(ServerSessionHandler):

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
        server = SSHServerSessionAuthHandler.SSHAuthenticationServer(self.authenticator)
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
