from nnc.auth import SSHClientSessionGenerator
from utils import file as fileutils
from utils.aes import AESCipherV2
from threading import Thread, Lock
import json
import os
import time
import socket
import logging

BUFFER_SIZE_DEFAULT = 4096


class NodeClient:
    def __init__(
        self,
        name,
        host,
        port,
        username=None,
        password=None,
        pkey=None,
        local_node_name: str = "",
        default_buffer_size: int = BUFFER_SIZE_DEFAULT,
    ):
        self.name = name
        self.host = host
        self.port = port
        self.local_node_name = local_node_name
        # auth
        self.username = username
        self.password = password
        self.pkey = pkey
        # common
        self.buffer_size = default_buffer_size
        # other
        self.index = 0
        self.cipher = None
        self.socket = None
        self.client_connector = SSHClientSessionGenerator()
        self.lock = Lock()

    def __str__(self):
        return f"NodeClient:{self.name}:{self.host}:{self.port}"

    def connect(self) -> bool:
        try:
            flag, channel = self.client_connector.generate(
                host=self.host,
                port=self.port,
                username=self.username,
                password=self.password,
                pkey=self.pkey,
            )
            if not flag:
                return False
            self.socket = channel
            key = self.socket.recv(self.buffer_size)
            self.cipher = AESCipherV2(key=key)
            return True
        except Exception as e:
            return False

    def close(self) -> None:
        if self.socket is None:
            return
        with self.lock:
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
                self.socket.sendall(
                    self._encode_message(
                        self.index,
                        __reqcmd,
                        *args,
                        **kwargs,
                        _reqnode=self.local_node_name,
                    )
                )
                post_handle_flag = True
                if post_handler:
                    print("debu")
                    post_handle_flag = post_handler(
                        *post_handler_args, **post_handler_kwargs
                    )
                response_data = self.socket.recv(4096)
                if not response_data:
                    if not self.connect():
                        raise ConnectionResetError("Server closed connection.")
                index, timestamp, reqcmd, args, kwargs = self._decode_message(
                    response_data
                )
                logging.debug(
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
                logging.error(f"[{self}] Error in send_request: {e}")
                return False, [str(e)], {}

    def rq_ping(self):
        """
        name: your node server name
        """
        try:
            flag, args, kwargs = self._send_request("ping")
            print(flag,args,kwargs)
            if flag and args[0]:
                return True
            return False
        except Exception as e:
            logging.error(f"[{self}] Error in rq_ping: {e}")
            return False

    def rq_route(self):
        client_flag, args, kwargs = self._send_request("route")
        if client_flag:
            return True, args[0]
        return False, f"Client Error: {args}"

    def rq_route_bridge_up(
        self, target: str, target_port: int, start: str, bridge_id: str | int
    ):
        client_flag, args, kwargs = self._send_request(
            "route_bridge_up",
            target=target,
            target_port=target_port,
            start=start,
            bridge_id=bridge_id,
        )
        if client_flag:
            return args[0], args[1]  # flag, port
        return False, f"Client Error: {args}"

    def rq_route_bridge_down(
        self, target: str, target_port: int, start: str, bridge_id: str | int
    ):
        client_flag, args, kwargs = self._send_request(
            "route_bridge_down",
            target=target,
            target_port=target_port,
            start=start,
            bridge_id=bridge_id,
        )
        if client_flag:
            return args[0]  # Flag
        return False

    def rq_cmd(self, cmd: str, target: str, origin: str):
        flag, args, kwargs = self._send_request(
            "cmd",
            cmd=cmd,
            target=target,
            origin=origin,
        )
        if flag:
            return args[0], args[1]  # args: returncode(int) and output(str)
        return False, f"Client Error: {args}"

    def rq_file_send(
        self,
        target: str,
        source_filepath: str,
        target_filepath: str,
        origin: str = None,
    ):
        """Send file/folder to target node

        Keyword arguments:
        target -- target node name
        origin -- origin node name, that is local node name
        source_filepath -- file/folder to be send
        target_filepath -- the path that file/folder to be stored
        Return: flag, message
        """
        if not origin:
            origin = self.local_node_name
        flag, files = fileutils.get_files(source_filepath)
        if not flag:
            return flag, files

        def post_handler(files):
            # send folders first
            for f in files:
                type = f[2]
                filename = f[1]
                filepath = f[0]
                filesize = os.path.getsize(filepath)
                if type == "D":
                    msg = json.dumps(
                        {"type": type, "filename": filename, "filesize": filesize}
                    )
                    self.socket.sendall(self.cipher.encrypt(msg.encode()))
                    item_resp = self.cipher.decrypt(self.socket.recv(self.buffer_size))
                    if item_resp != "ACK":
                        return False
            # then send files
            for f in files:
                type = f[2]
                filename = f[1]
                filepath = f[0]
                filesize = os.path.getsize(filepath)
                if type == "F":
                    msg = json.dumps(
                        {"type": type, "filename": filename, "filesize": filesize}
                    )
                    self.socket.sendall(self.cipher.encrypt(msg.encode()))
                    item_resp = self.cipher.decrypt(self.socket.recv(self.buffer_size))
                    if item_resp != "ACK":
                        return False
                    try:
                        with open(filepath, "rb") as f:
                            while True:
                                data = f.read(self.buffer_size)
                                if not data:
                                    break
                                self.socket.sendall(data)
                        # todo: check md5sum
                        item_resp = self.cipher.decrypt(
                            self.socket.recv(self.buffer_size)
                        )
                        if item_resp != "ACK":
                            return False
                    except Exception as e:
                        logging.error(f"[{self}] do file send: {e}")
                        return False
            pass

        flag, args, kwargs = self._send_request(
            "file_send",
            target=target,
            origin=origin,
            path=target_filepath,
            filenumber=len(files),
            __post_handler=post_handler,
            __post_handler_args=[files],
            __post_handler_kwargs={},
        )
        if flag:
            return args[0], args[1]
        return False, f"Client Error: {args}"

    def rq_file_recv(
        self,
        target: str,
        source_filepath: str,
        target_filepath: str,
        origin: str = None,
    ):
        """Recv file/folder from target node

        Keyword arguments:
        target -- target node name
        origin -- origin node name, that is local node name
        source_filepath -- file/folder to be send
        target_filepath -- the path that file/folder to be stored
        Return: flag, message
        """
        if not origin:
            origin = self.local_node_name

        os.mkdir(target_filepath)

        def post_handler(target_filepath):
            filenumber = int(self.cipher.decrypt(self.socket.recv(self.buffer_size)))
            is_item_resp = False
            try:
                for i in range(filenumber):
                    is_item_resp = False
                    file_item = json.loads(
                        self.cipher.decrypt(self.socket.recv(self.buffer_size))
                    )
                    type = file_item.get("type")
                    filename = file_item.get("filename")
                    filesize = file_item.get("filesize")
                    filepath = os.path.join(target_filepath, filename)
                    if type == "D":
                        os.mkdir(filepath)
                        self.socket.sendall(self.cipher.encrypt(b"ACK"))
                        is_item_resp = True
                    elif type == "F":
                        self.socket.sendall(self.cipher.encrypt(b"ACK"))
                        with open(filepath, "wb") as f:
                            received_size = 0
                            while received_size < filesize:
                                data = self.socket.recv(
                                    min(filesize - received_size, self.buffer_size)
                                )
                                if not data:
                                    break
                                f.write(data)
                                received_size += len(data)
                            self.socket.sendall(self.cipher.encrypt(b"ACK"))
                            is_item_resp = True
                    else:
                        self.socket.sendall(
                            self.cipher.encrypt(b"Error File Sending Protocol")
                        )
                        is_item_resp = True
                        raise Exception("Error File Sending Protocol")
            except Exception as e:
                logging.error(f"[{self}] do file send: {e}")
                if not is_item_resp:
                    try:
                        self.socket.sendall(
                            self.cipher.encrypt(f"Local:{self}:{e}".encode())
                        )
                    except Exception as ex:
                        pass
                return False
            return True

        flag, args, kwargs = self._send_request(
            "file_recv",
            target=target,
            origin=origin,
            path=source_filepath,
            __post_handler=post_handler,
            __post_handler_args=[target_filepath],
            __post_handler_kwargs={},
        )
        if flag:
            return args[0], args[1]
        return False, f"Client Error: {args}"
