import base64
import hashlib
import logging
import os

os.system('pip install pycryptodomex')
from Cryptodome import Random
from Cryptodome.Cipher import AES

logger = logging.getLogger(__file__)


class AESCipher(object):

    def __init__(self, key):
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, raw):
        raw = self._pack_data(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpack_data(cipher.decrypt(enc[AES.block_size:]))

    @staticmethod
    def _pack_data(s):
        return s + ((AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size)).encode(
            'utf-8')

    @staticmethod
    def _unpack_data(s):
        data = s[:-ord(s[len(s) - 1:])]
        if isinstance(data, bytes):
            data = data.decode('utf-8')
        return data


class AESBaseCrypt(object):

    def __init__(self):
        self.cipher = AESCipher(self.__class__.__name__)

    def set_encrypt_uid(self, key):
        return self.cipher.encrypt(key.encode('utf-8')).decode('utf-8')

    def get_decrypt_uid(self, enc):
        try:
            return self.cipher.decrypt(enc)
        except Exception as e:
            logger.warning(f'decrypt {enc} failed. exception:{e}')


class AESCipherV2(object):
    """
    前端操作
    import CryptoJS from "crypto-js";

    export function AesEncrypted(key: string, msg: string): string {
      return CryptoJS.AES.encrypt(msg, key).toString();
    }

    export function AesDecrypted(key: string, encryptedMessage: string): string {
      return CryptoJS.AES.decrypt(encryptedMessage, key).toString(
        CryptoJS.enc.Utf8
      );
    }
    """

    def __init__(self, key: str | bytes):
        self.key = key.encode('utf-8') if isinstance(key, str) else key

    def _make_key(self, salt, output=48):
        key = hashlib.md5(self.key + salt).digest()
        final_key = key
        while len(final_key) < output:
            key = hashlib.md5(key + self.key + salt).digest()
            final_key += key
        return final_key[:output]

    def encrypt(self, raw):
        salt = Random.new().read(8)
        key_iv = self._make_key(salt, 32 + 16)
        key = key_iv[:32]
        iv = key_iv[32:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return base64.b64encode(b"Salted__" + salt + cipher.encrypt(self._pack_data(raw)))

    def decrypt(self, enc: str | bytes) -> str:
        data = base64.b64decode(enc)
        if data[:8] != b'Salted__':
            return ''
        salt = data[8:16]
        key_iv = self._make_key(salt, 32 + 16)
        key = key_iv[:32]
        iv = key_iv[32:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return self._unpack_data(cipher.decrypt(data[AES.block_size:]))

    @staticmethod
    def _pack_data(s):
        return s + ((AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size)).encode(
            'utf-8')

    @staticmethod
    def _unpack_data(s):
        data = s[:-ord(s[len(s) - 1:])]
        if isinstance(data, bytes):
            data = data.decode('utf-8')
        return data

