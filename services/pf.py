import socket
import threading
import time
import logging
import json
import os

logger = logging.getLogger(__name__)

#
# Port Forwarder
#


class PortForwarder:
    class Protocol:
        TCP = "TCP"
        UDP = "UDP"

    def __init__(
        self,
        id,
        local_host,
        local_port,
        remote_host,
        remote_port,
        protocol=Protocol.TCP,
    ):
        self.id = id
        self.local_host = local_host
        self.local_port = local_port
        self.remote_host = remote_host
        self.remote_port = remote_port
        self.protocol = protocol
        self.running = False
        self.thread = None
        self.lock = threading.Lock()
        self.stop_event = threading.Event()

    def __str__(self) -> str:
        return f"[PortForwarder {self.id} | {self.local_host}:{self.local_port} -> {self.remote_host}:{self.remote_port}]"

    def start(self):
        with self.lock:
            if not self.running:
                self.running = True
                self.stop_event.clear()
                self.thread = threading.Thread(target=self._forward)
                self.thread.start()

    def stop(self):
        with self.lock:
            if self.running:
                self.running = False
                self.stop_event.set()
                if self.thread:
                    self.thread.join()

    def _forward(self):
        if self.protocol == PortForwarder.Protocol.TCP:
            self._forward_tcp()
        elif self.protocol == PortForwarder.Protocol.UDP:
            self._forward_udp()
        else:
            raise ValueError(
                f"[PortForwarder {self.id}] Unsupported protocol: {self.protocol}"
            )

    def _forward_tcp(self):
        local_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        local_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        local_socket.bind((self.local_host, self.local_port))
        local_socket.listen(5)
        local_socket.settimeout(5.0)
        logger.info(
            f"[PortForwarder {self.id}][TCP] started on {self.local_host}:{self.local_port}"
        )

        try:
            while self.running and not self.stop_event.is_set():
                try:
                    client_socket, addr = local_socket.accept()
                except Exception as e:
                    continue
                remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote_socket.connect((self.remote_host, self.remote_port))
                logger.info(
                    f"[PortForwarder {self.id}][{self.Protocol}] client connected from {addr[0]}:{addr[1]}"
                )

                client_to_remote = threading.Thread(
                    target=self._relay,
                    args=(client_socket, remote_socket),
                    kwargs={
                        "src_addr": addr,
                        "dst_addr": (self.remote_host, self.remote_port),
                    },
                )
                remote_to_client = threading.Thread(
                    target=self._relay,
                    args=(remote_socket, client_socket),
                    kwargs={
                        "dst_addr": addr,
                        "src_addr": (self.remote_host, self.remote_port),
                    },
                )

                client_to_remote.start()
                remote_to_client.start()
        finally:
            local_socket.close()
            logger.info(f"[PortForwarder {self.id}][{self.Protocol}] stopped")

    def _forward_udp(self):
        local_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        local_socket.bind((self.local_host, self.local_port))
        logger.info(
            f"[PortForwarder {self.id}][{self.Protocol}] started on {self.local_host}:{self.local_port}"
        )

        try:
            while self.running and not self.stop_event.is_set():
                data, addr = local_socket.recvfrom(4096)
                remote_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                remote_socket.sendto(data, (self.remote_host, self.remote_port))
                remote_socket.close()
        finally:
            local_socket.close()
            logger.info(f"[PortForwarder {self.id}][{self.Protocol}] stopped")

    def _relay(self, src, dst, src_addr=None, dst_addr=None):
        try:
            while self.running and not self.stop_event.is_set():
                data = src.recv(4096)
                if not data:
                    break
                dst.sendall(data)
        except Exception as e:
            if self.running:
                logger.error(
                    f"[PortForwarder {self.id}][{self.protocol}] Relay {src_addr}->{dst_addr} error: {e}"
                )
        finally:
            src.close()
            dst.close()


class PortForwarderManager:
    def __init__(self, save_path: str = None, auto_save: bool = True):
        self.save_path = save_path
        self.auto_save = auto_save
        self.forwarders: dict[str, PortForwarder] = {}
        self.lock = threading.Lock()
        if self.save_path:
            self.load()

    def __len__(self) -> int:
        return len(self.forwarders)

    def load(self, save_path=None):
        if not save_path and not self.save_path:
            raise ValueError("Save Path Not Set")
        if not save_path:
            save_path = self.save_path
        if not os.path.isfile(save_path):
            raise ValueError("Error Save Path, Should be a File Path")
        data = {}
        try:
            with open(save_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            with self.lock:
                for id, item in data.items():
                    if id in self.forwarders:
                        if (
                            self.forwarders[id].local_host != item["local_host"]
                            or self.forwarders[id].local_port != item["local_port"]
                            or self.forwarders[id].remote_host != item["remote_host"]
                            or self.forwarders[id].remote_port != item["remote_port"]
                            or self.forwarders[id].protocol != item["protocol"]
                        ):
                            self.forwarders[id].stop()
                            del self.forwarders[id]
                        else:
                            continue
                    pf = PortForwarder(
                        id,
                        item["local_host"],
                        item["local_port"],
                        item["remote_host"],
                        item["remote_port"],
                        item["protocol"],
                    )
                    self.forwarders[id] = pf
                    pf.start()
        except Exception as e:
            logging.error(f"PortForwarderManager Saving Error: {e}")

    def save(self, save_path=None):
        if not save_path and not self.save_path:
            raise ValueError("Save Path Not Set")
        if not save_path:
            save_path = self.save_path
        if not os.path.isfile(save_path):
            raise ValueError("Error Save Path, Should be a File Path")
        data = {}
        with self.lock:
            for id, forwarder in self.forwarders.items():
                data[id] = {
                    "local_host": forwarder.local_host,
                    "local_port": forwarder.local_port,
                    "remote_host": forwarder.remote_host,
                    "remote_port": forwarder.remote_port,
                    "protocol": forwarder.protocol,
                }
        try:
            with open(save_path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False)
        except Exception as e:
            logging.error(f"PortForwarderManager Saving Error: {e}")

    def add_forwarder(self, forwarder: PortForwarder):
        with self.lock:
            if forwarder.id in self.forwarders:
                raise ValueError(f"Forwarder with ID {forwarder.id} already exists")
            self.forwarders[forwarder.id] = forwarder
        if self.auto_save and self.save_path:
            self.save()

    def new_forwarder(
        self,
        id,
        local_host,
        local_port,
        remote_host,
        remote_port,
        protocol=PortForwarder.Protocol.TCP,
        auto_start=True,
    ):
        with self.lock:
            if id in self.forwarders:
                raise ValueError(f"Forwarder with ID {id} already exists")
            forwarder = PortForwarder(
                id, local_host, local_port, remote_host, remote_port, protocol
            )
            self.forwarders[id] = forwarder
            if auto_start:
                forwarder.start()
        if self.auto_save and self.save_path:
            self.save()

    def get_forwarder(self, id) -> PortForwarder:
        with self.lock:
            if id in self.forwarders:
                return self.forwarders[id]
            return None

    def start_forwarder(self, id):
        with self.lock:
            if id in self.forwarders:
                self.forwarders[id].start()
            else:
                raise ValueError(f"Forwarder with ID {id} does not exist")

    def stop_forwarder(self, id):
        with self.lock:
            if id in self.forwarders:
                self.forwarders[id].stop()
            else:
                raise ValueError(f"Forwarder with ID {id} does not exist")

    def delete_forwarder(self, id):
        with self.lock:
            if id in self.forwarders:
                self.forwarders[id].stop()
                del self.forwarders[id]
            else:
                raise ValueError(f"Forwarder with ID {id} does not exist")
        if self.auto_save and self.save_path:
            self.save()
