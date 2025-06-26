import socket
import asyncio
import uuid
import json
import time
from typing import List, Dict, Any
from random import random
from Crypto.Random import get_random_bytes
from pyshamir import split, combine
from Crypto.Hash import SHA256
import nacl.public
from DBFmodule import DBFCache



class DistributedSecretSharing:
    def __init__(self, 
                 eph_id_gen_interval: int,
                 k_min_shares: int,
                 n_total_shares: int,
                 broadcast_port: int = 12345,
                 broadcast_address: str = '255.255.255.255',
                 broadcast_interval: float = 3.0,
                 ):
        """
        Initialize the Distributed Secret Sharing Node
        
        Args:
            broadcast_port (int): UDP port for broadcasting
            broadcast_address (str): Broadcast IP address
            broadcast_interval (float): Seconds between share broadcasts
        """
        # Unique identifier for this node
        self.node_id = str(uuid.uuid4())
        
        # Network configuration
        self.broadcast_port = broadcast_port
        self.broadcast_address = broadcast_address
        self.broadcast_interval = broadcast_interval
        self.eph_id_gen_interval = eph_id_gen_interval
        self.k_min_shares = k_min_shares
        self.n_total_shares = n_total_shares

        # Server configuration
        self.server_address = '127.0.0.1'  
        self.server_port = 55000  
        self.covid_positive = False  

        # Networking setup
        self.broadcast_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.broadcast_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        
        # State management
        self.current_secret = None
        self.current_priv_key = None
        self.current_shares = []
        self.received_shares: Dict[str, Dict[int, bytes]] = {}
        self.reconstructed_secrets: Dict[str, bytes] = {}

        # Bloom filters
        self.dbf_cache = DBFCache(eph_id_gen_interval)  
        self.Dt_seconds = ((eph_id_gen_interval * 6 * 6) / 60) * 60 
        self.current_qbf = None


    def generate_random_id(self) -> bytes:
        """
        Generate a cryptographically secure 32-byte random ID
        
        Returns:
            bytes: 32-byte random ID
        """
        return get_random_bytes(32)
    
    def generate_ephemeral_keypair(self):
        private_key = nacl.public.PrivateKey.generate()
        public_key = private_key.public_key
        ephemeral_id = bytes(public_key)  # 32 bytes for X25519
        return private_key, ephemeral_id
    
    def compute_encounter_id(self, my_private_key, other_ephemeral_id):
        # Convert ephemeral ID back to public key format
        other_public_key = nacl.public.PublicKey(other_ephemeral_id)

        # Logging private and public key details
        my_private_key_bytes = bytes(my_private_key)
        my_public_key_bytes = bytes(my_private_key.public_key)
        print(f"Using Diffie-Hellman:\n  priv key = {my_private_key_bytes.hex()[:8]}...\n  pub key  = {my_public_key_bytes.hex()[:8]}...")

        # Compute shared secret
        box = nacl.public.Box(my_private_key, other_public_key)
        encounter_id = box.shared_key()
        return encounter_id

    def split_secret(self, secret: bytes) -> List:
        """
        Split the secret using PyCryptodome's Secret Sharing
        
        Args:
            secret (bytes): Secret to be split
        
        Returns:
            List of shares
        """
        return split(secret, self.n_total_shares, self.k_min_shares)

    def reconstruct_secret(self, shares: List) -> bytes:
        """
        Reconstruct the secret from received shares
        
        Args:
            shares (List[bytes]): Shares to reconstruct from
        
        Returns:
            bytes: Reconstructed secret
        """
        return combine(shares)

    async def broadcast_message(self, message_type: str, content: Any):
        """
        Broadcast a message to the network
        
        Args:
            message_type (str): Type of message
            content (Any): Message content
        """
        # Prepare message with node ID and type
        message = {
            'node_id': self.node_id,
            'type': message_type,
            'content': content
        }
        
        # Convert to JSON and send
        serialized_message = json.dumps(message).encode('utf-8')
        
        try:
            self.broadcast_socket.sendto(
                serialized_message, 
                (self.broadcast_address, self.broadcast_port)
            )
            print(f"Broadcasted {message_type} index {content['index']} share {content['share'][0:8]}...")
        except Exception as e:
            print(f"Error broadcasting message: {e}")

    async def generate_and_share_secret(self):
        """
        Generate a new secret and share it across the network
        """
        while True:
            # Generate new secret
            self.node_id = str(uuid.uuid4())
            self.current_priv_key, self.current_secret = self.generate_ephemeral_keypair()
            share_hash = SHA256.new(self.current_secret).hexdigest()
            
            print(f"Node [{self.node_id[0:10]}] Generated new EphID: {self.current_secret.hex()[0:8]}...")
            
            # Split secret into shares
            self.current_shares = self.split_secret(self.current_secret)
            # Assuming self.current_secret is a list or iterable of bytes objects
            hex_list = [element.hex()[0:8] for element in self.current_shares]

            # If you need to print it with formatting:
            print(f"Node [{self.node_id[0:10]}] Secret elements: {', '.join(hex_list)}")
            
            # Broadcast each share with delay
            for index, share in enumerate(self.current_shares, 1):
                await self.broadcast_message('share', {
                    'index': index,
                    'share': share.hex(),
                    'eph_id_hash': share_hash
                })

                
                # Wait between broadcasts
                await asyncio.sleep(self.broadcast_interval)
            

    async def receive_messages(self):
        """
        Receive and process network messages
        """
        # Create UDP socket for receiving
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        sock.bind(('0.0.0.0', self.broadcast_port))
        sock.setblocking(False)
        
        loop = asyncio.get_event_loop()
        
        while True:
            try:
                # Use loop.sock_recvfrom for non-blocking receive
                data, _ = await loop.sock_recvfrom(sock, 1024)

                # 50% prob of dropping packet
                # if random() < 0.5:
                #     continue
                                
                # Parse received message
                try:
                    message = json.loads(data.decode('utf-8'))
                    
                    # Ignore messages from self
                    if message['node_id'] == self.node_id:
                        continue

                    if random() < 0.50:
                        print(f"Packet dropped from node {message['node_id']}")
                        continue
                    
                    # Process share messages
                    if message['type'] == 'share':
                        self.process_share_message(message)
                    
                except (json.JSONDecodeError, KeyError) as e:
                    print(f"Error parsing message: {e}")
            
            except Exception as e:
                # Handle other potential errors
                print(f"Error in message receiving: {e}")
            
            # Prevent tight loop
            await asyncio.sleep(0.1)

    def process_share_message(self, message: Dict[Any, Any]):
        """
        Process incoming share messages
        
        Args:
            message (Dict): Received share message
        """
        try:
            # Extract share details
            sender_id = message['node_id']
            share_index = message['content']['index']
            share_hex = message['content']['share']
            eph_id_hash = message['content']['eph_id_hash']
            
            # Convert hex share back to bytes
            share = bytes.fromhex(share_hex)
            
            # Initialize received shares for this sender if not exists
            if sender_id not in self.received_shares:
                self.received_shares[sender_id] = {}
            
            # Store received share
            self.received_shares[sender_id][share_index] = share

            print(f"Recieved another share: {len(self.received_shares[sender_id])}/{self.k_min_shares} recieved")
            
            # Check if we can reconstruct secret for this sender
            if len(self.received_shares[sender_id]) >= self.k_min_shares and sender_id not in self.reconstructed_secrets:
                try:
                    #verify hashes


                    # Attempt to reconstruct secret
                    shares_list = list(self.received_shares[sender_id].values())
                    reconstructed_secret = self.reconstruct_secret(shares_list)
                    
                    # Store reconstructed secret
                    self.reconstructed_secrets[sender_id] = reconstructed_secret
                    print(f"Node [{self.node_id[0:10]}] Reconstructed secret from {sender_id[0:10]}: {reconstructed_secret.hex()[0:8]}...")

                    # compute the EncID
                    enc_id = self.compute_encounter_id(self.current_priv_key, bytes(reconstructed_secret))
                    print(f"Node [{self.node_id[0:10]}] Computed EncID: {enc_id.hex()[0:8]}...")

                    self.dbf_cache.add_encid(enc_id)
                    del enc_id
                    print("Deleted EncID")


                except Exception as e:
                    print(f"Error reconstructing secret: {e}")
        
        except Exception as e:
            print(f"Error processing share message: {e}")

    async def report_positive(self):
        """User reports positive COVID-19 diagnosis and uploads CBF"""
        
        
        # Create CBF from all DBFs
        cbf = self.dbf_cache.combine_dbfs()
        if not cbf:
            print("No contact data available to report")
            return False
        
        # Upload CBF to server
        success = await self.upload_cbf_to_server(cbf)
        if success:
            self.covid_positive = True
            print("Successfully reported COVID-positive status")
            return True
        else:
            print("Failed to report COVID-positive status")
            return False

    async def upload_cbf_to_server(self, cbf):
        """Upload Contact Bloom Filter to server via TCP"""
        try:
            # Connect to server
            reader, writer = await asyncio.open_connection(
                self.server_address, self.server_port)
            
            # Prepare message
            message = {
                'type': 'cbf_upload',
                'node_id': self.node_id,
                'cbf': cbf.to_bytes().hex()  # Convert bloom filter to bytes then hex
            }
            
            # Send message
            writer.write(json.dumps(message).encode('utf-8') + b'\n')
            await writer.drain()
            
            # Get response
            response = await reader.readline()
            response_data = json.loads(response.decode('utf-8'))
            
            # Close connection
            writer.close()
            await writer.wait_closed()
            
            return response_data.get('success', False)
        
        except Exception as e:
            print(f"Error uploading CBF: {e}")
            return False

    async def check_exposure(self):
        """Send QBF to server to check for COVID-19 exposure"""
        if self.covid_positive:
            print("This node has already reported as COVID-positive")
            return None
        
        # Create QBF from DBFs
        qbf = self.dbf_cache.combine_dbfs()
        if not qbf:
            print("No contact data available to check")
            return None
        
        try:
            # Connect to server
            reader, writer = await asyncio.open_connection(
                self.server_address, self.server_port)
            
            # Prepare message
            message = {
                'type': 'qbf_check',
                'node_id': self.node_id,
                'qbf': qbf.to_bytes().hex()  # Convert bloom filter to bytes then hex
            }
            
            # Send message
            writer.write(json.dumps(message).encode('utf-8') + b'\n')
            await writer.drain()
            
            # Get response
            response = await reader.readline()
            response_data = json.loads(response.decode('utf-8'))
            
            # Close connection
            writer.close()
            await writer.wait_closed()
            
            exposure_result = response_data.get('exposure', False)
            print(f"Exposure check result: {'EXPOSED' if exposure_result else 'NOT EXPOSED'}")
            return exposure_result
        
        except Exception as e:
            print(f"Error checking exposure: {e}")
        return None
    
    async def periodic_exposure_check(self):
        """Periodically check for COVID-19 exposure"""
        while not self.covid_positive:  # Stop checking if diagnosed positive
            print("Combining all DBFs into a QBF and sending...")
            await self.check_exposure()
            # Check every hour (can be adjusted)
            await asyncio.sleep(self.Dt_seconds)

    async def handle_user_commands(self):
        """Handle user commands via command line"""
        print("COVID-19 Contact Tracing Node Started")
        print("Commands: report - Report COVID-positive, check - Check exposure, status - Show status, quit - Exit")
        
        while True:
            try:
                # Non-blocking input using asyncio
                command = await asyncio.to_thread(input, "\nEnter command:\n")
                
                if command.lower() == 'report':
                    if self.covid_positive:
                        print("Already reported as COVID-positive")
                    else:
                        print("Reporting COVID-19 positive status...")
                        success = await self.report_positive()
                        if success:
                            print("Successfully reported. Your contact information has been uploaded.")
                            print("The system will no longer generate QBFs for privacy protection.")
                        else:
                            print("Failed to report status. Please try again later.")
                
                elif command.lower() == 'check':
                    print("Checking for potential COVID-19 exposure...")
                    await self.check_exposure()
                
                elif command.lower() == 'status':
                    status = "COVID-POSITIVE (reported)" if self.covid_positive else "No positive report"
                    print(f"Node ID: {self.node_id}")
                    print(f"Status: {status}")
                    print(f"DBFs count: {len(self.dbf_cache.dbfs)}")
                    print(f"Last DBF timestamp: {time.ctime(self.dbf_cache.current_dbf.timestamp)}")
                
                elif command.lower() in ['quit', 'exit']:
                    print("Shutting down...")
                    return
                
                else:
                    print("Unknown command. Available commands: report, check, status, quit")
            
            except Exception as e:
                print(f"Error processing command: {e}")
            
            # Prevent tight loop
            await asyncio.sleep(0.1)

    async def run(self):
        """
        Run the distributed secret sharing node
        """
        await asyncio.gather(
            self.handle_user_commands(),
            self.periodic_exposure_check(),
            self.generate_and_share_secret(),
            self.receive_messages(),
        )

