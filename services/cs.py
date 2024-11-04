from threading import Thread, Lock, Event
import socket
from threading import Thread
import json
import logging
import time
from services.abc import BaseService
from utils.aes import AESCipherV2

logger = logging.getLogger(__name__)

#
# client / server
#

BUFFER_SIZE_DEFAULT = 4096


class SecureSocketBaseService(BaseService):
    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 10001,
        username: str = "",
        password: str = "",
        key: str = "",
        default_buffer_size: int = BUFFER_SIZE_DEFAULT,
    ):
        self.buffer_size = default_buffer_size
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.key = key
        super().__init__()

    def __str__(self):
        return f"SecureSocketBaseService:{self.host}:{self.port}"

    def _handle_request(self, __reqcmd, *args, **kwargs):
        handler = getattr(self, f"do_{__reqcmd}", None)
        if handler:
            # handler should return tuple[args:tuple|list, kwargs:dict]
            return handler(*args, **kwargs)
        return args, kwargs

    def _handle_client(self, conn, addr):
        logger.debug(f"[{self}] Connected by {addr}")
        serial = 0
        try:
            self._valid_password(conn)
            while True:
                data = conn.recv(self.buffer_size)
                if not data:
                    break
                index, timestamp, reqcmd, args, kwargs = self._decode_message(data)
                if index == serial:
                    if serial == 9999:
                        serial = 0
                    else:
                        serial += 1
                else:
                    break
                logger.debug(
                    f"[{self}][{addr}] Received {index}: {reqcmd}, Args: {args}, Kwargs: {kwargs}"
                )
                ret = self._handle_request(
                    reqcmd, *args, **kwargs, _address=addr, _socket=conn
                )
                if ret is not None:
                    if (
                        len(ret) == 2
                        and (type(ret[0]) == tuple or type(ret[0]) == list)
                        and type(ret[1]) == dict
                    ):
                        res_args, res_kwargs = ret
                    elif type(ret) == dict:
                        res_args, res_kwargs = [], ret
                    elif len(ret) > 0:
                        res_args, res_kwargs = ret, {}
                    else:
                        res_args, res_kwargs = [], {}
                else:
                    res_args, res_kwargs = [], {}
                self._send_response(conn, index, reqcmd, *res_args, **res_kwargs)
        except Exception as e:
            logger.error(f"[{self}][{addr}]Error: {e}")
        finally:
            conn.close()

    def _encode_message(self, __index, __reqcmd, *args, **kwargs) -> bytes:
        return self.cipher.encrypt(
            json.dumps(
                {
                    "index": __index,
                    "timestamp": int(time.time() * 1000),
                    "reqcmd": __reqcmd,
                    "args": list(args),
                    "kwargs": kwargs,
                }
            ).encode("utf-8")
        )

    def _decode_message(self, __message) -> tuple[int, int, str, list, dict]:
        data = json.loads(self.cipher.decrypt(__message))
        return (
            data["index"],
            data["timestamp"],
            data["reqcmd"],
            data.get("args", []),
            data.get("kwargs", {}),
        )

    def _valid_password(self, conn) -> bool:
        data = conn.recv(self.buffer_size)
        if not data:
            return False
        index, timestamp, reqcmd, args, kwargs = self._decode_message(data)
        if index != -1:
            return False
        if (
            reqcmd != "password"
            and kwargs["username"] != self.username
            and kwargs["password"] != self.password
        ):
            return False
        self._send_response(conn, index, reqcmd, True)
        return True

    def _send_response(self, __conn, __index, __reqcmd, *args, **kwargs) -> None:
        encrypted_response = self._encode_message(__index, __reqcmd, *args, **kwargs)
        __conn.sendall(encrypted_response)

    def run(self) -> None:
        self._running = True
        while (
            not self._running_stop_event.is_set()
            and not self.host
            and not self.port
            and not self.key
        ):
            # wait for the server to be ready
            time.sleep(0.5)
        self.cipher = AESCipherV2(key=self.key)
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind((self.host, self.port))
        self.socket.listen()
        while not self._running_stop_event.is_set():
            self.run_main_loop()
        self._running = False

    def run_main_loop(self) -> None:
        conn, addr = self.socket.accept()
        client_thread = Thread(target=self._handle_client, args=(conn, addr))
        client_thread.start()

    def stop(self) -> None:
        super().stop()
        self.socket.close()


class SecureSocketBaseClient:
    def __init__(
        self,
        host,
        port,
        username,
        password,
        key,
        default_buffer_size: int = BUFFER_SIZE_DEFAULT,
    ):
        self.buffer_size = default_buffer_size
        self.host = host
        self.port = port
        self.key = key
        self.username = username
        self.password = password
        self.cipher = AESCipherV2(key=key)
        self.socket = None
        self.index = 0
        self.lock = Lock()

    def __str__(self):
        return f"SecureSocketBaseClient:{self.host}:{self.port}"

    def connect(self) -> bool:
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((self.host, self.port))
        return self._valid_password()

    def disconnect(self) -> None:
        if self.socket is not None:
            self.socket.close()
            self.socket = None

    def _encode_message(self, __index, __reqcmd, *args, **kwargs) -> bytes:
        return self.cipher.encrypt(
            json.dumps(
                {
                    "index": __index,
                    "timestamp": int(time.time() * 1000),
                    "reqcmd": __reqcmd,
                    "args": list(args),
                    "kwargs": kwargs,
                }
            ).encode("utf-8")
        )

    def _decode_message(self, __message) -> tuple[int, int, str, list, dict]:
        data = json.loads(self.cipher.decrypt(__message))
        return (
            data["index"],
            data["timestamp"],
            data["reqcmd"],
            data.get("args", []),
            data.get("kwargs", {}),
        )

    def _valid_password(self) -> bool:
        index, reqcmd = -1, "password"
        self._send_message(
            index, reqcmd, username=self.username, password=self.password
        )
        response_data = self.socket.recv(self.buffer_size)
        if not response_data:
            return False
        _index, timestamp, _reqcmd, args, kwargs = self._decode_message(response_data)
        if _index == index and _reqcmd == reqcmd and args[0]:
            return True
        return False

    def _send_message(self, __index, __reqcmd, *args, **kwargs) -> None:
        encrypted_response = self._encode_message(__index, __reqcmd, *args, **kwargs)
        self.socket.sendall(encrypted_response)

    def _send_request(self, __reqcmd, *args, **kwargs) -> tuple[bool, list, dict]:
        with self.lock:
            try:
                if self.socket is None:
                    if not self.connect():
                        raise ConnectionError("Client is not connected.")
                post_handler = kwargs.get("__post_handler", None)
                post_handler_args = kwargs.get("__post_handler_args", [])
                post_handler_kwargs = kwargs.get("__post_handler_kwargs", {})
                for k in list(kwargs.keys()):
                    if k.startswith("__"):
                        del kwargs[k]
                self._send_message(self.index, __reqcmd, *args, **kwargs)
                post_handle_flag = True
                if post_handler:
                    print('debu')
                    post_handle_flag = post_handler(*post_handler_args, **post_handler_kwargs)
                response_data = self.socket.recv(4096)
                if not response_data:
                    if not self.connect():
                        raise ConnectionResetError("Server closed connection.")
                index, timestamp, reqcmd, args, kwargs = self._decode_message(
                    response_data
                )
                logger.debug(
                    f"[{self}] Received {index}, {timestamp}, {reqcmd}, Args: {args}, Kwargs: {kwargs}"
                )
                if self.index != index:
                    return False, ["Error in response index."], {}
                if reqcmd != __reqcmd:
                    return False, ["Error in response reqcmd."], {}
                if self.index == 9999:
                    self.index = 0
                else:
                    self.index += 1
                return True, list(args), kwargs
            except Exception as e:
                logger.error(f"[{self}] Error in send_request: {e}")
                return False, [str(e)], {}
