import subprocess
from nnc.client import NodeClient
from nnc.auth import SSHAuthenticator, SSHServerSessionAuthHandler

from services.abc import BaseService
from services.pf import PortForwarderManager
from utils.portpool import PortPool
from utils import file as fileutils
from utils.lock import ReadWriteLock
from utils.aes import AESCipherV2
from threading import Thread, Lock
import paramiko
import socket
import time
import json
import os
import logging

BUFFER_SIZE_DEFAULT = 4096


class NodeService(BaseService):
    def __init__(
        self,
        name: str,
        host: str,
        port: int,
        username: str,
        pkey: str | bytes,
        authenticator: SSHAuthenticator,
        is_block_unknown_node: bool = True,
        port_pool_range: tuple = (11000, 12000),
        default_buffer_size: int = BUFFER_SIZE_DEFAULT,
    ):
        self.name = name
        self.host = host
        self.port = port
        # security
        self.username = username
        self.pkey = (
            paramiko.RSAKey.from_private_key_file(pkey)
            if os.path.isfile(pkey)
            else pkey
        )
        self.authenticator = authenticator
        self.authhandler = SSHServerSessionAuthHandler(authenticator=authenticator)
        self.is_block_unknown_node = is_block_unknown_node
        # other nodes info
        self.node_info_list: list[NodeClient] = []
        self.node_info_dict: dict[str, NodeClient] = {}
        self.node_info_lock = ReadWriteLock()
        # route_dict[nodename][nodename] = True/False
        self.route_dict: dict[str, dict[str, bool]] = {}
        # common
        self.buffer_size = default_buffer_size
        # other
        self.pfpp = PortPool(*port_pool_range)
        self.pfm = PortForwarderManager()
        self.route_lock = ReadWriteLock()
        super().__init__()

    def __str__(self):
        return f"NodeService:{self.name}:{self.host}:{self.port}"

    def _encode_message(self, __index, __reqcmd, __cipher, *args, **kwargs) -> bytes:
        return __cipher.encrypt(
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

    def _decode_message(self, __message, __cipher) -> tuple[int, int, str, list, dict]:
        data = json.loads(__cipher.decrypt(__message))
        return (
            data["index"],
            data["timestamp"],
            data["reqcmd"],
            data.get("args", []),
            data.get("kwargs", {}),
        )

    def _handle_client(self, conn, addr):
        if self.is_block_unknown_node:
            # block unknown ip
            if addr[0] not in [node.host for node in self.node_info_list]:
                conn.close()
                return
        logging.debug(f"[{self}] Connected by {addr}")
        try:
            flag, channel = self.authhandler.handle(socket=conn, addr=addr)
            if not flag:
                raise Exception(f"Authentication failed!")
            key = os.urandom(32)
            cipher = AESCipherV2(key=key)
            channel.sendall(key)
            serial = 0
            while True:
                data = channel.recv(self.buffer_size)
                if not data:
                    break
                index, timestamp, reqcmd, args, kwargs = self._decode_message(
                    data, cipher
                )
                if index == serial:
                    if serial == 9999:
                        serial = 0
                    else:
                        serial += 1
                else:
                    break
                logging.debug(
                    f"[{self}][{addr}][{kwargs.get('_reqnode')}] Received {index}: {reqcmd}, Args: {args}, Kwargs: {kwargs}"
                )
                ret = self._handle_client_request(
                    reqcmd,
                    *args,
                    **kwargs,
                    _address=addr,
                    _socket=channel,
                    _cipher=cipher,
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
                logging.debug(
                    f"[{self}][{addr}][{kwargs.get('_reqnode')}] Response {index}: Args: {res_args}, Kwargs: {res_kwargs}"
                )
                channel.sendall(
                    self._encode_message(index, reqcmd, cipher, *res_args, **res_kwargs)
                )
        except Exception as e:
            logging.error(f"[{self}][{addr}][{kwargs.get('_reqnode')}] Error {index}: {e}")
        finally:
            channel.close()

    def _handle_client_request(self, __reqcmd, *args, **kwargs):
        if self.is_block_unknown_node:
            # block unknown node name
            if (
                "_reqnode" not in kwargs
                or kwargs["_reqnode"] not in [node.name for node in self.node_info_list]
                or self.node_info_dict[kwargs["_reqnode"]].host != kwargs["_address"][0]
            ):
                raise Exception(
                    f"Unknown Request Node: _reqnode={kwargs.get('_reqnode')}"
                )
        handler = getattr(self, f"do_{__reqcmd}", None)
        if handler:
            # handler should return tuple[args:tuple|list, kwargs:dict]
            return handler(*args, **kwargs)
        return args, kwargs

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

    def sv_node_add(self, name, host, port):
        nodeinfo = NodeClient(
            name,
            host,
            port,
            username=self.username,
            pkey=self.pkey,
            local_node_name=self.name,
        )
        self.node_info_lock.acquire_write()
        if name in self.node_info_dict:
            return False
        self.node_info_list.append(nodeinfo)
        self.node_info_dict[name] = nodeinfo
        self.node_info_lock.release_write()
        return True

    def sv_node_get(self, name):
        """Generate Node Client

        Keyword arguments:
        name -- node name
        Return: node client of node
        """

        node_base = self.node_info_dict.get(name, None)
        node = NodeClient(
            name,
            host=node_base.host,
            port=node_base.port,
            local_node_name=self.name,
        )
        return node

    def sv_route_update(self):
        # {name: {name: True, name: True, ...}, name: {name: True, name: True, ...}}
        routes = {node.name: {} for node in self.node_info_list + [self]}

        for node in self.node_info_list + [self]:
            for other_node in self.node_info_list + [self]:
                if node.name != other_node.name:
                    routes[node.name][other_node.name] = False
                else:
                    routes[node.name][node.name] = True

        for node in self.node_info_list:
            routes[self.name][node.name] = node.rq_ping()

        self.route_lock.acquire_write()
        self.route_dict = routes.copy()
        self.route_lock.release_write()

        for node in self.node_info_list:
            if routes[self.name][node.name]:
                flag, nodes_routes = node.rq_route()
                if not flag:
                    continue
                for name_start, name_target_dict in nodes_routes.items():
                    if name_start == self.name:
                        continue
                    for name_target, reachable in name_target_dict.items():
                        routes[name_start][name_target] = reachable

        self.route_lock.acquire_write()
        self.route_dict = routes.copy()
        self.route_lock.release_write()

    def sv_route_query(self, target: str, start: str = None):
        if start is None:
            start = self.name

        self.route_lock.release_read()
        route_dict = self.route_dict.copy()
        self.route_lock.release_read()

        if target not in route_dict.keys() or start not in route_dict.keys():
            return False, None
        visited = {name: False for name in route_dict.keys()}
        queue = [(start, [start])]
        reachability = (
            {}
        )  # {target: [path], target: [path], ...}, path(start!=target): [start, (...,) target], path(start==target): [start]

        while len(queue) > 0:
            cur_name, path = queue.pop(0)
            if not visited[cur_name]:
                visited[cur_name] = True
                reachability[cur_name] = path
                for neighbor_name in visited.keys():
                    if (
                        route_dict[cur_name][neighbor_name]
                        and not visited[neighbor_name]
                    ):
                        new_path = path + [neighbor_name]
                        queue.append((neighbor_name, new_path))
        if target not in reachability:
            return False, f"No Route to {target}"
        return True, reachability[target]

    def sv_route_bridge_up(
        self, target: str, target_port: int, start: str, bridge_id: str | int
    ):
        # TCP only
        if target == self.name:
            # target is own
            return True, target_port

        self.route_lock.release_read()
        route_dict = self.route_dict.copy()
        self.route_lock.release_read()

        if route_dict[self.name][target]:
            # can reach directly
            # create port forward to target
            try:
                target_node = self.sv_node_get(target)
                target_host = target_node.host
                local_port = self.pfpp.allocate()
                forwarder_id = f"[bridge:{start}:{bridge_id}]:{self.name}->{target}"
                forwarder = self.pfm.get_forwarder(forwarder_id)
                if forwarder is not None:
                    return True, forwarder.local_port
                self.pfm.new_forwarder(
                    forwarder_id,
                    local_host=self.host,
                    local_port=local_port,
                    remote_host=target_host,
                    remote_port=target_port,
                )
                self.pfm.start_forwarder(forwarder_id)
                logging.info(
                    f"[{self}] route bridge up: [bridge:{start}:{bridge_id}]:{self.name}->{target} created"
                )
                return True, local_port
            except Exception as e:
                msg = f"failed to set up forward on self node {self.name} to reach {target}:{target_port}: {e}"
                logging.error(f"[{self}] route bridge up: {msg}")
                try:
                    self.pfpp.release(local_port)
                except Exception as e:
                    pass
                try:
                    self.pfm.delete_forwarder(forwarder_id)
                except Exception as e:
                    pass
                return False, msg
        flag, path = self.sv_route_query(target)
        if flag and len(path) >= 3:
            # reachable by bridge, that is other node can reach
            bridge_node_name = path[1]
            bridge_node = self.sv_node_get(bridge_node_name)
            # set up remote bridge
            flag, remote_port = bridge_node.rq_route_bridge_up(
                target=target,
                target_port=target_port,
                start=start,
                bridge_id=bridge_id,
            )
            if not flag:
                msg = f"failed to require set up bridge on node {bridge_node_name} to reach {target}:{target_port}. node {bridge_node_name} return: {remote_port}"
                logging.error(f"[{self}] route bridge up: {msg}")
                return False, msg
            logging.info(
                f"[{self}] route bridge up: [bridge:{start}:{bridge_id}] created by remote node {bridge_node_name}, remote port {remote_port}"
            )
            # set up local bridge
            flag, local_port = self.sv_route_bridge_up(
                target=bridge_node_name,
                target_port=remote_port,
                start=start,
                bridge_id=bridge_id,
            )
            if not flag:
                # delete remote bridge
                bridge_node.rq_route_bridge_down(
                    target=target,
                    target_port=target_port,
                    start=start,
                    bridge_id=bridge_id,
                )
                return False, local_port
            return True, local_port
        msg = f"no path to reach {target}:{target_port}."
        logging.error(f"[{self}] route bridge up: {msg}")
        return False, msg

    def sv_route_bridge_down(
        self, target: str, target_port: int, start: str, bridge_id: str | int
    ):
        target_node = self.sv_node_get(target)
        forwarder = None
        if target == self.name:
            # target is own
            return True

        self.route_lock.release_read()
        route_dict = self.route_dict.copy()
        self.route_lock.release_read()

        if route_dict[self.name][target]:
            # can reach directly
            # free forwarder and port to target
            forwarder_id = f"[bridge:{start}:{bridge_id}]:{self.name}->{target}"
            forwarder = self.pfm.get_forwarder(forwarder_id)
        flag, path = self.sv_route_query(target)
        if flag and len(path) >= 3:
            # reachable by bridge, that is other node can reach
            bridge_node_name = path[1]
            bridge_node = self.sv_node_get(bridge_node_name)
            forwarder_id = (
                f"[bridge:{start}:{bridge_id}]:{self.name}->{bridge_node_name}"
            )
            forwarder = self.pfm.get_forwarder(forwarder_id)
            if forwarder is not None:
                # set down remote bridge
                bridge_node.rq_route_bridge_down(
                    target=target,
                    target_port=target_port,
                    start=start,
                    bridge_id=bridge_id,
                )
        if forwarder is not None:
            # free self forwarder and port
            logging.info(f"[{self}] route bridge down: delete {forwarder}")
            try:
                self.pfpp.release(forwarder.local_port)
            except Exception as e:
                pass
            try:
                self.pfm.delete_forwarder(forwarder.id)
            except Exception as e:
                pass
        return True

    def sv_cmd(self, cmd: str, target: str, origin: str):
        if target == self.name:
            # target is own
            try:
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                return True, [
                    result.returncode,
                    result.stdout.strip(),
                    result.stderr.strip(),
                ]
            except Exception as e:
                return False, str(e)
        flag, path = self.sv_route_query(target)
        if flag and len(path) >= 2:
            jump_node_name = path[1]
            jump_node = self.sv_node_get(jump_node_name)
            flag, result = jump_node.rq_cmd(cmd=cmd, target=target, origin=origin)
            if not flag:
                return False, result
            return True, result
        msg = f"no path to reach {target}."
        logging.error(f"[{self}] cmd: {msg}")
        return False, msg

    def sv_file_send(
        self,
        target: str,
        source_filepath: str,
        target_filepath: str,
    ):
        flag, node_route_path = self.sv_route_query(target)
        if flag and len(node_route_path) > 0:
            jump_node_name = node_route_path[0 if target == self.name else 1]
            jump_node = self.sv_node_get(jump_node_name)
            flag, msg = jump_node.rq_file_send(
                target=target,
                source_filepath=source_filepath,
                target_filepath=target_filepath,
                origin=self.name,
            )
            return flag, msg
        msg = f"no path to reach {target}."
        logging.error(f"[{self}] cmd: {msg}")
        return False, msg

    def sv_file_recv(
        self,
        target: str,
        source_filepath: str,
        target_filepath: str,
    ):
        flag, node_route_path = self.sv_route_query(target)
        if flag and len(node_route_path) > 0:
            jump_node_name = node_route_path[0 if target == self.name else 1]
            jump_node = self.sv_node_get(jump_node_name)
            flag, msg = jump_node.rq_file_recv(
                target=target,
                source_filepath=source_filepath,
                target_filepath=target_filepath,
                origin=self.name,
            )
            return flag, msg
        msg = f"no path to reach {target}."
        logging.error(f"[{self}] cmd: {msg}")
        return False, msg

    def do_ping(self, *args, **kwargs):
        # debug ----start
        if logging.getLogger().getEffectiveLevel() == logging.DEBUG:
            node_name = kwargs.get("_reqnode")
            if self.name == "node1" and node_name == "node3":
                return [False, node_name], {}
            if self.name == "node3" and node_name == "node1":
                return [False, node_name], {}
        # debug ----end
        return [True, kwargs.get("_reqnode")], {}

    def do_route(self, *args, **kwargs):

        self.route_lock.release_read()
        route_dict = self.route_dict.copy()
        self.route_lock.release_read()

        return [route_dict], {}

    def do_route_bridge_up(self, *args, **kwargs):
        ret_args, ret_kwargs = [], {}
        target = kwargs.get("target", None)
        target_port = kwargs.get("target_port", None)
        start = kwargs.get("start", None)
        bridge_id = kwargs.get("bridge_id", None)
        if not (target and target_port and start and bridge_id):
            return [False, "Invalid Params"], {}
        ret_args = self.sv_route_bridge_up(
            target=target,
            target_port=target_port,
            start=start,
            bridge_id=bridge_id,
        )
        return ret_args, ret_kwargs

    def do_route_bridge_down(self, *args, **kwargs):
        ret_args, ret_kwargs = [], {}
        target = kwargs.get("target", None)
        target_port = kwargs.get("target_port", None)
        start = kwargs.get("start", None)
        bridge_id = kwargs.get("bridge_id", None)
        if not (target and target_port and start and bridge_id):
            return [False, "Invalid Params"], {}
        ret_args = self.sv_route_bridge_down(
            target=target,
            target_port=target_port,
            start=start,
            bridge_id=bridge_id,
        )
        return ret_args, ret_kwargs

    def do_cmd(self, *args, **kwargs):
        ret_args, ret_kwargs = [], {}
        cmd = kwargs.get("cmd", None)
        target = kwargs.get("target", None)
        origin = kwargs.get("origin", None)
        if not (cmd and target and origin):
            return [False, "Invalid Params"], {}
        ret_args = self.sv_cmd(cmd=cmd, target=target, origin=origin)
        return ret_args, ret_kwargs

    def do_file_send(self, *args, **kwargs):
        ret_args, ret_kwargs = [], {}
        target = kwargs.get("target", None)
        origin = kwargs.get("origin", None)
        path = kwargs.get("path", None)
        filenumber = kwargs.get("filenumber", None)
        address = kwargs.get("_address", None)
        socket = kwargs.get("_socket", None)
        cipher = kwargs.get("_cipher", None)
        if not (target and origin and path and filenumber):
            return [False, "Invalid Params"], {}
        if target == self.name:
            os.mkdir(path)
            # target is own
            is_item_resp = False
            try:
                for i in range(filenumber):
                    is_item_resp = False
                    file_item = json.loads(
                        cipher.decrypt(socket.recv(self.buffer_size))
                    )
                    type = file_item.get("type")
                    filename = file_item.get("filename")
                    filesize = file_item.get("filesize")
                    filepath = os.path.join(path, filename)
                    if type == "D":
                        os.mkdir(filepath)
                        socket.sendall(cipher.encrypt(b"ACK"))
                        is_item_resp = True
                    elif type == "F":
                        socket.sendall(cipher.encrypt(b"ACK"))
                        with open(filepath, "wb") as f:
                            received_size = 0
                            while received_size < filesize:
                                data = socket.recv(
                                    min(filesize - received_size, self.buffer_size)
                                )
                                if not data:
                                    break
                                f.write(data)
                                received_size += len(data)
                            socket.sendall(cipher.encrypt(b"ACK"))
                            is_item_resp = True
                    else:
                        socket.sendall(cipher.encrypt(b"NOACK"))
                        is_item_resp = True
                        ret_args = [False, "Error File Sending Protocol"]
                        raise Exception("Error File Sending Protocol")
                # todo: check md5sum
            except Exception as e:
                logging.error(f"[{self}] do file send: {e}")
                if not is_item_resp:
                    try:
                        socket.sendall(cipher.encrypt(b"NOACK"))
                    except Exception as ex:
                        pass
                return [False, str(e)], ret_kwargs
            return [True, None], ret_kwargs
        flag, node_route_path = self.sv_route_query(target)
        if flag and len(node_route_path) >= 2:
            jump_node_name = node_route_path[1]
            jump_node = self.sv_node_get(jump_node_name)

            def post_handler(
                self,
                filenumber,
                localservice: NodeService,
                localsocket,
                remoteclient: NodeClient,
                remotesocket,
            ):
                is_item_resp = False
                try:
                    for i in range(filenumber):
                        is_item_resp = False
                        file_item_raw = localservice.cipher.decrypt(
                            localsocket.recv(localservice.buffer_size)
                        )
                        remotesocket.sendall(
                            remoteclient.cipher.encrypt(file_item_raw.encode())
                        )
                        resq = json.loads(file_item_raw)
                        type = resq.get("type")
                        filename = resq.get("filename")
                        filesize = resq.get("filesize")
                        if type == "D":
                            item_resp = remoteclient.cipher.decrypt(
                                remotesocket.recv(remoteclient.buffer_size)
                            )
                            localsocket.sendall(
                                localservice.cipher.encrypt(item_resp.encode())
                            )
                            is_item_resp = True
                            if item_resp != "ACK":
                                return False
                        elif type == "F":
                            item_resp = remoteclient.cipher.decrypt(
                                remotesocket.recv(remoteclient.buffer_size)
                            )
                            localsocket.sendall(
                                localservice.cipher.encrypt(item_resp.encode())
                            )
                            is_item_resp = True
                            if item_resp != "ACK":
                                return False
                            received_size = 0
                            while received_size < filesize:
                                data = localsocket.recv(
                                    min(
                                        filesize - received_size,
                                        localservice.buffer_size,
                                    )
                                )
                                remotesocket.sendall(data)
                                if not data:
                                    break
                                received_size += len(data)
                            item_resp = remoteclient.cipher.decrypt(
                                remotesocket.recv(remoteclient.buffer_size)
                            )
                            localsocket.sendall(
                                localservice.cipher.encrypt(item_resp.encode())
                            )
                            is_item_resp = True
                            if item_resp != "ACK":
                                return False
                        else:
                            item_resp = remoteclient.cipher.decrypt(
                                remotesocket.recv(remoteclient.buffer_size)
                            )
                            localsocket.sendall(
                                localservice.cipher.encrypt(item_resp.encode())
                            )
                            is_item_resp = True
                            if item_resp != "ACK":
                                ret_args = [False, "Error File Sending Protocol"]
                                raise Exception("Error File Sending Protocol")
                    # todo: check md5sum
                except Exception as e:
                    logging.error(f"[{localservice}] jp do file send: {e}")
                    if not is_item_resp:
                        try:
                            localservice.sendall(localservice.cipher.encrypt(b"NOACK"))
                        except Exception as ex:
                            pass
                    return False
                return True

            flag, args, kwargs = jump_node._send_request(
                "file_send",
                target=target,
                origin=origin,
                path=path,
                filenumber=filenumber,
                __post_handler=post_handler,
                __post_handler_args=[
                    self,
                    filenumber,
                    self,
                    socket,
                    jump_node,
                    jump_node.socket,
                ],
                __post_handler_kwargs={},
            )
            # if flag:
            return args, kwargs
        msg = f"no path to reach {target}."
        logging.error(f"[[{self}] file_send: {msg}")
        return [False, msg], ret_kwargs

    def do_file_recv(self, *args, **kwargs):
        ret_args, ret_kwargs = [], {}
        target = kwargs.get("target", None)
        origin = kwargs.get("origin", None)
        path = kwargs.get("path", None)
        address = kwargs.get("_address", None)
        socket = kwargs.get("_socket", None)
        cipher = kwargs.get("_cipher", None)
        if not (target and origin and path):
            socket.sendall(cipher.encrypt(b"0"))
            return [False, "Invalid Params"], ret_kwargs
        if target == self.name:
            # target is own
            flag, files = fileutils.get_files(path)
            if not flag:
                return [flag, files], ret_kwargs
            socket.sendall(cipher.encrypt(str(len(files)).encode()))
            for f in files:
                type = f[2]
                filename = f[1]
                filepath = f[0]
                filesize = os.path.getsize(filepath)
                if type == "D":
                    msg = json.dumps(
                        {"type": type, "filename": filename, "filesize": filesize}
                    )
                    socket.sendall(cipher.encrypt(msg.encode()))
                    item_resp = cipher.decrypt(socket.recv(self.buffer_size))
                    if item_resp != "ACK":
                        return [False, item_resp], ret_kwargs
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
                    socket.sendall(cipher.encrypt(msg.encode()))
                    item_resp = cipher.decrypt(socket.recv(self.buffer_size))
                    if item_resp != "ACK":
                        return [False, item_resp], ret_kwargs
                    try:
                        with open(filepath, "rb") as f:
                            while True:
                                data = f.read(self.buffer_size)
                                if not data:
                                    break
                                socket.sendall(data)
                        # todo: check md5sum
                        item_resp = cipher.decrypt(socket.recv(self.buffer_size))
                        if item_resp != "ACK":
                            return [False, item_resp], ret_kwargs
                    except Exception as e:
                        logging.error(f"[{self}] do file send: {e}")
                        return [False, item_resp], ret_kwargs
            return [True, None], ret_kwargs
        flag, node_route_path = self.sv_route_query(target)
        if flag and len(node_route_path) >= 2:
            jump_node_name = node_route_path[1]
            jump_node = self.sv_node_get(jump_node_name)

            def post_handler(
                self,
                localservice: NodeService,
                localsocket,
                remoteclient: NodeClient,
                remotesocket,
            ):
                is_item_resp = False
                try:
                    file_number_raw = remoteclient.cipher.decrypt(
                        remotesocket.recv(remoteclient.buffer_size)
                    )
                    localsocket.sendall(
                        localservice.cipher.encrypt(file_number_raw.encode())
                    )
                    for i in range(int(file_number_raw)):
                        is_item_resp = False
                        file_item_raw = remoteclient.cipher.decrypt(
                            remotesocket.recv(remoteclient.buffer_size)
                        )
                        localsocket.sendall(
                            localservice.cipher.encrypt(file_item_raw.encode())
                        )
                        file_item = json.loads(file_item_raw)
                        type = file_item.get("type")
                        filename = file_item.get("filename")
                        filesize = file_item.get("filesize")
                        # filepath = os.path.join(path, filename)
                        if type == "D":
                            # os.mkdir(filepath)
                            item_resp = localservice.cipher.decrypt(
                                localsocket.recv(localservice.buffer_size)
                            )
                            remotesocket.sendall(
                                remoteclient.cipher.encrypt(item_resp.encode())
                            )
                            is_item_resp = True
                            if item_resp != "ACK":
                                return False
                        elif type == "F":
                            item_resp = localservice.cipher.decrypt(
                                localsocket.recv(localservice.buffer_size)
                            )
                            remotesocket.sendall(
                                remoteclient.cipher.encrypt(item_resp.encode())
                            )
                            is_item_resp = True
                            if item_resp != "ACK":
                                return False
                            received_size = 0
                            while received_size < filesize:
                                data = remotesocket.recv(
                                    min(
                                        filesize - received_size,
                                        localservice.buffer_size,
                                    )
                                )
                                localsocket.sendall(data)
                                if not data:
                                    break
                                received_size += len(data)
                            item_resp = localservice.cipher.decrypt(
                                localsocket.recv(localservice.buffer_size)
                            )
                            remotesocket.sendall(
                                remoteclient.cipher.encrypt(item_resp.encode())
                            )
                            is_item_resp = True
                            if item_resp != "ACK":
                                return False
                        else:
                            item_resp = localservice.cipher.decrypt(
                                localsocket.recv(localservice.buffer_size)
                            )
                            remotesocket.sendall(
                                remoteclient.cipher.encrypt(item_resp.encode())
                            )
                            is_item_resp = True
                            if item_resp != "ACK":
                                ret_args = [False, "Error File Sending Protocol"]
                                raise Exception("Error File Sending Protocol")
                    # todo: check md5sum
                except Exception as e:
                    logging.error(f"[{localservice}] jp do file send: {e}")
                    if not is_item_resp:
                        try:
                            remotesocket.sendall(
                                localservice.cipher.encrypt(f"{self}:{e}")
                            )
                        except Exception as ex:
                            pass
                    return False
                return True

            flag, args, kwargs = jump_node._send_request(
                "file_recv",
                target=target,
                origin=origin,
                path=path,
                __post_handler=post_handler,
                __post_handler_args=[
                    self,
                    self,
                    socket,
                    jump_node,
                    jump_node.socket,
                ],
                __post_handler_kwargs={},
            )
            # if flag:
            return args, kwargs
        msg = f"no path to reach {target}."
        logging.error(f"[[{self}] file_recv: {msg}")
        socket.sendall(cipher.encrypt(b"0"))
        return [False, msg], ret_kwargs
