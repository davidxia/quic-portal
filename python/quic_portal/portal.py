import logging
import os
import socket as socketlib
import time
from typing import Optional, Union, Any

from ._core import QuicPortal as _QuicPortal, QuicTransportOptions as _QuicTransportOptions
from .exceptions import ConnectionError
from .nat import get_stun_response

# Simple logger setup.
logger = logging.getLogger("quic_portal")
logger.setLevel(logging.INFO)
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("[%(name)s] [%(asctime)s] %(levelname)s: %(message)s"))
    logger.addHandler(handler)
    logger.propagate = False

# Enable debug logging for Quinn specifically.
quinn_logger = logging.getLogger("quinn")
quinn_logger.setLevel(logging.WARN)
if not quinn_logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("[%(name)s] [%(asctime)s] %(levelname)s: %(message)s"))
    quinn_logger.addHandler(handler)
    logger.propagate = False

quinn_logger = logging.getLogger("quinn_proto")
if not quinn_logger.handlers:
    quinn_logger.setLevel(logging.WARN)
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("[%(name)s] [%(asctime)s] %(levelname)s: %(message)s"))
    quinn_logger.addHandler(handler)
    logger.propagate = False

quinn_logger = logging.getLogger("quinn_udp")
quinn_logger.setLevel(logging.WARN)
if not quinn_logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("[%(name)s] [%(asctime)s] %(levelname)s: %(message)s"))
    quinn_logger.addHandler(handler)
    logger.propagate = False


class QuicTransportOptions:
    """Configuration options for QUIC transport."""

    def __init__(
        self,
        max_idle_timeout_secs: int = 10,
        congestion_controller_type: str = "cubic",
        initial_window: int = 1024 * 1024,  # 1MiB
        keep_alive_interval_secs: int = 2,
    ):
        """
        Initialize QUIC transport options.

        Args:
            max_idle_timeout_secs: Maximum idle timeout in seconds
            congestion_controller_type: Congestion controller type ("cubic", "bbr", "fixed")
            initial_window: Initial window size in bytes
            keep_alive_interval_secs: Keep alive interval in seconds
        """
        self._core = _QuicTransportOptions()
        self._core.max_idle_timeout_secs = max_idle_timeout_secs
        self._core.congestion_controller_type = congestion_controller_type
        self._core.initial_window = initial_window
        self._core.keep_alive_interval_secs = keep_alive_interval_secs

    @property
    def max_idle_timeout_secs(self) -> int:
        return self._core.max_idle_timeout_secs

    @max_idle_timeout_secs.setter
    def max_idle_timeout_secs(self, value: int):
        self._core.max_idle_timeout_secs = value

    @property
    def congestion_controller_type(self) -> str:
        return self._core.congestion_controller_type

    @congestion_controller_type.setter
    def congestion_controller_type(self, value: str):
        self._core.congestion_controller_type = value

    @property
    def initial_window(self) -> int:
        return self._core.initial_window

    @initial_window.setter
    def initial_window(self, value: int):
        self._core.initial_window = value

    @property
    def keep_alive_interval_secs(self) -> int:
        return self._core.keep_alive_interval_secs

    @keep_alive_interval_secs.setter
    def keep_alive_interval_secs(self, value: int):
        self._core.keep_alive_interval_secs = value


def get_socket(local_port: int) -> socketlib.socket:
    """Get a socket with large buffers and non-blocking behavior."""
    sock = socketlib.socket(socketlib.AF_INET, socketlib.SOCK_DGRAM)
    sock.setsockopt(socketlib.SOL_SOCKET, socketlib.SO_RCVBUF, 64 * 1024 * 1024)
    sock.setsockopt(socketlib.SOL_SOCKET, socketlib.SO_SNDBUF, 64 * 1024 * 1024)
    sock.setsockopt(socketlib.SOL_SOCKET, socketlib.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", local_port))
    sock.settimeout(0.1)  # 100ms timeout for non-blocking behavior during punching.
    return sock


class Portal:
    """
    High-level QUIC portal for bidirectional communication.

    Can be used directly after NAT traversal, or use the static methods
    create_client() and create_server() for automatic NAT traversal.

    Example (manual):
        # After NAT hole punching is complete...
        portal = Portal()
        portal.connect("192.168.1.100", 5555, local_port=5556)

        # Send messages (WebSocket-style)
        portal.send(b"Hello, QUIC!")

        # Receive messages (blocks until message arrives)
        data = portal.recv(timeout_ms=1000)
        if data:
            print(f"Received: {data}")

    Example (automatic NAT traversal):
        import modal

        # Server side
        with modal.Dict.ephemeral() as coord_dict:
            server_portal = Portal.create_server(dict=coord_dict, local_port=5555)

        # Client side
        with modal.Dict.ephemeral() as coord_dict:
            client_portal = Portal.create_client(dict=coord_dict, local_port=5556)
    """

    def __init__(self):
        self._core = _QuicPortal()
        self._connected = False

        # Only set for client end of portal.
        self.server_ip = None
        self.server_port = None

    @staticmethod
    def _send_burst(sock: socketlib.socket, addr: tuple[str, int], data: bytes, log_prefix: str) -> None:
        """
        Send a small burst of data to improve reliability against UDP loss/NAT timing.
        """
        src_ip, src_port = sock.getsockname()
        for _ in range(5):
            logger.debug(
                f"{log_prefix} SEND {data!r} 5-tuple: {src_ip}:{src_port} -> {addr[0]}:{addr[1]} UDP"
            )
            sock.sendto(data, addr)
            time.sleep(0.03)

    @staticmethod
    def get_local_ip() -> str:
        s = socketlib.socket(socketlib.AF_INET, socketlib.SOCK_DGRAM)
        try:
            # Connect to a public server (doesn't send data) to get the local IP
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
        except Exception:
            local_ip = "127.0.0.1"  # Fallback to localhost if connection fails
        finally:
            s.close()
        return local_ip

    @staticmethod
    def create_server(
        dict: Any,
        local_port: int = 5555,
        stun_servers: list[tuple[str, int]] = [
            ("stun.ekiga.net", 3478),
            ("stun.l.google.com", 19302),
        ],
        punch_timeout: int = 15,
        transport_options: Optional[QuicTransportOptions] = None,
    ) -> "Portal":
        """
        Create a QUIC server with automatic NAT traversal.

        Args:
            dict: Modal Dict or dict-like object for coordination
            local_port: Local port to bind to
            stun_servers: List of STUN servers for NAT discovery
            punch_timeout: Timeout for NAT punching in seconds
            transport_options: QUIC transport configuration options

        Returns:
            Connected Portal instance
        """

        cloud_provider = os.getenv("MODAL_CLOUD_PROVIDER", "unknown")
        region = os.getenv("MODAL_REGION", "unknown")
        dict["server_cloud_provider"] = cloud_provider
        dict["server_region"] = region

        sock = get_socket(local_port)

        try:
            # Get external IP/port via STUN
            pub_addrs = Portal._get_ext_addr(sock, stun_servers)
            logger.debug(f"[server] Server local IP address: {Portal.get_local_ip()}")
            logger.debug(f"[server] Public endpoints: {pub_addrs}")

            # Register with coordination dict and wait for client
            client_endpoints = []
            while not client_endpoints:
                pub_addrs = Portal._get_ext_addr(sock, stun_servers)
                logger.debug(f"[server] Public endpoints: {pub_addrs}")

                dict["server"] = pub_addrs
                if "client" in dict:
                    client_endpoint = dict["client"]
                    if isinstance(client_endpoint[0], str):
                        # Old version added (ip, port) tuple
                        client_endpoints.append(client_endpoint)
                    else:
                        # New version added list of (ip, port) tuples
                        client_endpoints.extend(client_endpoint)

                    logger.debug(f"[server] Got client endpoints: {client_endpoints}")
                    break
                logger.debug("[server] Waiting for client to register...")
                time.sleep(0.2)

            # Add coordination delay to avoid race conditions
            # This is critical: server should wait for client to start punching first
            # to handle symmetric NATs properly
            logger.debug("[server] Waiting for client to establish initial NAT mapping...")
            time.sleep(1.0)  # Give client time to start punching and establish mapping

            # Use these to establish mappings at server-side NAT
            client_addrs_to_hit = set(client_endpoints)
            foo = set(client_endpoints)

            # Punch NAT
            punch_success = False
            start_time = time.time()
            attempts = 0

            logger.info(f"[server] Starting NAT punch to {len(client_addrs_to_hit)} client endpoints")

            while time.time() - start_time < punch_timeout:
                for endpoint in foo:
                    Portal._send_burst(sock, endpoint, b"punch", "[server]")

                n = 0
                for endpoint in client_addrs_to_hit:
                    src_ip, src_port = sock.getsockname()
                    if attempts >= 30 and n % attempts == 0:
                        logger.debug(
                            f"[server] SEND punch 5-tuple: {src_ip}:{src_port} -> {endpoint[0]}:{endpoint[1]} UDP"
                        )
                    sock.sendto(b"punch", endpoint)
                    n += 1

                try:
                    data, addr = sock.recvfrom(1024)
                    dst_ip, dst_port = sock.getsockname()
                    logger.debug(
                        f"[server] RECV 5-tuple: {addr[0]}:{addr[1]} -> {dst_ip}:{dst_port} UDP data={data!r}"
                    )
                    if data == b"punch":
                        Portal._send_burst(sock, addr, b"punch-ack", "[server]")

                        # Briefly linger to re-ack any duplicate punches to align with NAT timing windows
                        linger_deadline = min(time.time() + 1.0, start_time + punch_timeout)
                        while time.time() < linger_deadline:
                            try:
                                data2, addr2 = sock.recvfrom(1024)
                                logger.debug(
                                    f"[server] RECV 5-tuple: {addr2[0]}:{addr2[1]} -> {dst_ip}:{dst_port} UDP data={data2!r}"
                                )
                                if data2 == b"punch":
                                    Portal._send_burst(sock, addr2, b"punch-ack", "[server]")
                            except socketlib.timeout:
                                # Keep looping until linger timeout
                                pass

                        punch_success = True
                        break
                except socketlib.timeout:
                    attempts += 1
                    # Expand search space gradually for symmetric NATs
                    client_ips = set(addr[0] for addr in client_endpoints)

                    if attempts == 10:  # After 10 attempts, try nearby ports
                        logger.debug("[server] Expanding to nearby ports for symmetric NAT (-10 to 10 from base port)")
                        for client_ip in client_ips:
                            for base_port in [ep[1] for ep in client_endpoints]:
                                for offset in range(-10, 11):
                                    port = base_port + offset
                                    if 1024 <= port <= 65535:
                                        client_addrs_to_hit.add((client_ip, port))
                    elif attempts == 30:  # After 30 attempts, try broader range
                        logger.debug("[server] Expanding to broader port range 1000-9999 for symmetric NAT")
                        for client_ip in client_ips:
                            for _port in range(1000, 9999):
                                client_addrs_to_hit.add((client_ip, _port))
                    elif attempts == 60:  # After 60 attempts, try broadest range
                        logger.debug("[server] Expanding to broader port range 1000-65535 for symmetric NAT")
                        for client_ip in client_ips:
                            for _port in range(1000, 65535):
                                client_addrs_to_hit.add((client_ip, _port))

                    time.sleep(0.1)
                    continue

            if not punch_success:
                raise ConnectionError(f"Failed to punch NAT with client from cloud {cloud_provider} in region {region}")

            # Close UDP socket before QUIC can use the port
            sock.close()
            logger.info("[server] nat traversal successful")

            # Wait a moment to ensure socket is properly closed
            time.sleep(0.1)

            # Create Portal and start listening
            portal = Portal()
            portal.listen(local_port, transport_options or QuicTransportOptions())

            return portal

        except Exception as e:
            sock.close()
            raise ConnectionError(f"Server creation failed: {e}")

    @staticmethod
    def create_client(
        dict: Any,
        local_port: int = 5556,
        stun_servers: list[tuple[str, int]] = [
            ("stun.ekiga.net", 3478),
            ("stun.l.google.com", 19302),
        ],
        punch_timeout: int = 15,
        transport_options: Optional[QuicTransportOptions] = None,
    ) -> "Portal":
        """
        Create a QUIC client with automatic NAT traversal.

        Args:
            dict: Modal Dict or dict-like object for coordination
            local_port: Local port to bind to
            stun_servers: List of STUN servers for NAT discovery
            punch_timeout: Timeout for NAT punching in seconds
            transport_options: QUIC transport configuration options

        Returns:
            Connected Portal instance
        """

        sock = get_socket(local_port)

        try:
            # Register with coordination dict and wait for server
            server_endpoints = []
            while not server_endpoints:
                client_pub_addrs = Portal._get_ext_addr(sock, stun_servers)
                logger.debug(f"[client] Public endpoints (STUN): {client_pub_addrs}")

                dict["client"] = client_pub_addrs
                if "server" in dict:
                    server_endpoint = dict["server"]
                    if isinstance(server_endpoint[0], str):
                        # Old version added (ip, port) tuple
                        server_endpoints.append(server_endpoint)
                    else:
                        # New version added list of (ip, port) tuples
                        server_endpoints.extend(server_endpoint)
                    logger.debug(f"[client] Got server endpoint: {server_endpoint}")
                    break
                logger.debug("[client] Waiting for server to register...")
                time.sleep(0.2)

            # Server should be fairly stable, so just use first one.
            server_ip, server_port = server_endpoints[0]
            allowed_server_ips = {ip for (ip, _port) in server_endpoints}

            # Punch NAT
            punch_success = False
            start_time = time.time()
            punch_attempts = 0
            server_cloud_provider = dict.get("server_cloud_provider", "not set")
            server_region = dict.get("server_region", "not set")

            while time.time() - start_time < punch_timeout:
                src_ip, src_port = sock.getsockname()
                logger.debug(
                    f"[client] SEND punch 5-tuple: {src_ip}:{src_port} -> {server_ip}:{server_port} UDP"
                )
                Portal._send_burst(sock, (server_ip, server_port), b"punch", "[client]")
                try:
                    data, addr = sock.recvfrom(1024)
                    dst_ip, dst_port = sock.getsockname()
                    logger.debug(
                        f"[client] RECV 5-tuple: {addr[0]}:{addr[1]} -> {dst_ip}:{dst_port} UDP data={data!r}"
                    )
                    if data == b"punch-ack" and addr[0] in allowed_server_ips:
                        logger.debug("[client] Received punch-ack from server (expected addr)")
                        punch_success = True
                        break
                    else:
                        logger.debug(f"[client] Message {data!r} from {addr}, continuing to wait for punch-ack")
                        continue
                except socketlib.timeout:
                    punch_attempts += 1
                    if punch_attempts % 20 == 0:
                        logger.debug(f"[client] No packets received after {punch_attempts} attempts ({time.time() - start_time:.1f}s)")
                    time.sleep(0.1)
                    continue

            if not punch_success:
                raise ConnectionError(f"Failed to punch NAT with server {server_ip}:{server_port} from cloud {server_cloud_provider} in region {server_region}")

            logger.debug("[client] Punch successful, establishing QUIC connection")

            # Close UDP socket before QUIC can use the port
            sock.close()
            logger.info(f"[client] nat traversal successful with server {server_ip}:{server_port} from cloud {server_cloud_provider} in region {server_region}")

            # Wait a moment to ensure socket is properly closed
            time.sleep(0.05)

            # Create Portal and connect
            portal = Portal()
            portal.connect(server_ip, server_port, local_port, transport_options or QuicTransportOptions())

            return portal

        except Exception as e:
            sock.close()
            raise ConnectionError(f"Client creation failed: {e}")

    @staticmethod
    def _get_ext_addr(sock, stun_servers):
        """Get external IP and port using STUN."""
        responses = [get_stun_response(sock, stun_server) for stun_server in stun_servers]
        return [(response["ext_ip"], response["ext_port"]) for response in responses]

    def connect(self, server_ip: str, server_port: int, local_port: Optional[int] = None, transport_options: Optional[QuicTransportOptions] = None) -> None:
        """
        Connect to a QUIC server (after NAT traversal is complete).

        Args:
            server_ip: Server IP address
            server_port: Server port
            local_port: Local port to bind to (required)
            transport_options: QUIC transport configuration options
        """
        if local_port is None:
            raise ValueError("local_port is required for connect()")

        try:
            core_options = (transport_options or QuicTransportOptions())._core
            self._core.connect(server_ip, server_port, local_port, core_options)
            self._connected = True
            self.server_ip = server_ip
            self.server_port = server_port
            logger.debug(f"[PORTAL] QUIC connection established to {server_ip}:{server_port}")
        except Exception as e:
            raise ConnectionError(f"Failed to connect: {e}") from e

    def listen(self, local_port: Optional[int] = None, transport_options: Optional[QuicTransportOptions] = None) -> None:
        """
        Start QUIC server and wait for connection (after NAT traversal is complete).

        Args:
            local_port: Local port to bind to (required)
            transport_options: QUIC transport configuration options
        """
        if local_port is None:
            raise ValueError("local_port is required for listen()")

        try:
            core_options = (transport_options or QuicTransportOptions())._core
            self._core.listen(local_port, core_options)
            self._connected = True
            logger.debug(f"[PORTAL] QUIC server started on port {local_port}")
        except Exception as e:
            raise ConnectionError(f"Failed to start server: {e}") from e

    def send(self, data: Union[bytes, str]) -> None:
        """
        Send data over QUIC (WebSocket-style: no response expected).

        Args:
            data: Data to send (bytes or string)
        """
        if not self._connected:
            raise ConnectionError("Not connected. Call connect() first.")

        if isinstance(data, str):
            data = data.encode("utf-8")

        self._core.send(data)

    def recv(self, timeout_ms: Optional[int] = None) -> Optional[bytes]:
        """
        Receive data from QUIC connection (WebSocket-style: blocks until message arrives).

        Args:
            timeout_ms: Timeout in milliseconds (None for blocking)

        Returns:
            Received data as bytes, or None if timeout
        """
        if not self._connected:
            raise ConnectionError("Not connected. Call connect() first.")

        return self._core.recv(timeout_ms)

    def is_connected(self) -> bool:
        """Check if connected to QUIC server."""
        return self._core.is_connected()

    def close(self) -> None:
        """Close all connections."""
        self._core.close()
        self._connected = False
