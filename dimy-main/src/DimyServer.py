#!/usr/bin/env python3
"""
covid_backend_server.py

This module implements a TCP server for COVID-19 contact tracing.
It handles receiving Contact Bloom Filters (CBFs) from COVID-19 positive users
and processes Query Bloom Filters (QBFs) from users checking for exposure.
"""

import asyncio
import json
import traceback
import logging
import time
from Crypto.Hash import SHA256
from typing import Dict, List, Optional
from BloomFilter import BloomFilter 

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("COVID_Backend")

class COVIDBackendServer:
    def __init__(self, host: str = '0.0.0.0', port: int = 55000, cbf_retention_days: int = 14):
        """
        Initialize the COVID-19 Backend Server
        
        Args:
            host (str): Host address to bind the server
            port (int): Port to listen on
            cbf_retention_days (int): Number of days to retain CBFs
        """
        self.host = host
        self.port = port
        self.cbf_retention_days = cbf_retention_days
        
        # Store received CBFs with timestamps
        self.cbfs: List[Dict] = []
        
        # Statistics
        self.stats = {
            'cbf_uploads': 0,
            'qbf_checks': 0,
            'exposures_detected': 0
        }

    def load_bloom_filter_from_hex(self, hex_data: str) -> Optional[BloomFilter]:
        """Convert hex string back to BloomFilter object"""

        try:
            # Convert hex string to bytes
            binary_data = bytes.fromhex(hex_data)
            
            # Create a BloomFilter from binary data
            bf = BloomFilter.from_bytes(binary_data)
        
            return bf
        except Exception as e:
            print(e)
            logger.info(f"Error loading bloom filter: {e}")
            logger.error(f"Error loading bloom filter: {e}")
            return None

    def check_exposure(self, qbf: BloomFilter) -> bool:
        """
        Check if a QBF has any overlap with stored CBFs
        
        Args:
            qbf: Query Bloom Filter to check
            
        Returns:
            bool: True if exposure detected, False otherwise
        """
        # First ensure we've cleaned expired CBFs
        
        # No CBFs to check against
        if not self.cbfs:
            return False
            
        # Check against each stored CBF
        print(f"Comparing QBF to CBFs")
        for i, cbf_entry in enumerate(self.cbfs):
            cbf = cbf_entry['cbf']
            
            # Check for intersection
            # This will vary based on your BloomFilter implementation
            # In general, we're looking for matching bits
            if cbf.has_intersection(qbf):
                print(f"CBF {i+1}: MATCHED")
                self.stats['exposures_detected'] += 1
                return True
            print(f"CBF {i+1}: NOT MATCHED")
                
        return False

    async def handle_client(self, reader, writer):
        """Handle an individual client connection"""
        addr = writer.get_extra_info('peername')
        logger.info(f"New connection from {addr}")
        
        try:

            # Read client message
            data = await reader.readuntil(b'\n')
            # logger.info("yooooo")
            if not data:
                logger.warning(f"Empty data received from {addr}")
                return
                
            # Parse message
            message = json.loads(data.decode('utf-8'))
            message_type = message.get('type')
            node_id = message.get('node_id', 'unknown')

            
            
            response = {'success': False}
            
            if message_type == 'cbf_upload':
                # Handle CBF upload from COVID-positive user
                logger.info(f"Received CBF upload from node {node_id}")
                
                cbf_hex = message.get('cbf')
                print(SHA256.new(bytes.fromhex(cbf_hex)).hexdigest())
                if not cbf_hex:
                    response = {'success': False, 'error': 'Missing CBF data'}
                else:
                    # Convert hex to BloomFilter
                    cbf = self.load_bloom_filter_from_hex(cbf_hex)
                    if cbf != None:

                        # Store CBF with timestamp
                        self.cbfs.append({
                            'node_id': node_id,
                            'cbf': cbf,
                            'timestamp': time.time()
                        })
                        self.stats['cbf_uploads'] += 1
                        response = {'success': True}
                        logger.info(f"Successfully stored CBF from node {node_id}")
                    else:
                        response = {'success': False, 'error': 'Invalid CBF format'}
                
            elif message_type == 'qbf_check':
                # Handle exposure check request
                logger.info(f"Received exposure check from node {node_id}")
                self.stats['qbf_checks'] += 1
                
                qbf_hex = message.get('qbf')
                if not qbf_hex:
                    response = {'success': False, 'error': 'Missing QBF data'}
                else:
                    # Convert hex to BloomFilter
                    qbf = self.load_bloom_filter_from_hex(qbf_hex)
                    if qbf != None:
                        # Check for exposure
                        exposure = self.check_exposure(qbf)
                        response = {
                            'success': True,
                            'exposure': exposure
                        }
                        logger.info(f"Exposure check for {node_id}: {'EXPOSED' if exposure else 'NOT EXPOSED'}")
                    else:
                        response = {'success': False, 'error': 'Invalid QBF format'}
            
            else:
                # Unknown message type
                logger.warning(f"Unknown message type '{message_type}' from {addr}")
                response = {'success': False, 'error': 'Unknown message type'}
                
            # Send response
            writer.write(json.dumps(response).encode('utf-8') + b'\n')
            await writer.drain()
            
        except json.JSONDecodeError:
            logger.error(f"Invalid JSON received from {addr}")
            writer.write(json.dumps({'success': False, 'error': 'Invalid JSON'}).encode('utf-8') + b'\n')
            await writer.drain()
            
        except Exception as e:
            logger.error(f"Error handling client {addr}: {e}")
            print(traceback.format_exc())
            writer.write(json.dumps({'success': False, 'error': 'Server error'}).encode('utf-8') + b'\n')
            await writer.drain()

            
        finally:
            # Close connection
            writer.close()
            await writer.wait_closed()
            logger.info(f"Connection closed with {addr}")

    async def run_server(self):
        """Start the server"""
        server = await asyncio.start_server(
            self.handle_client, self.host, self.port)
            
        addr = server.sockets[0].getsockname()
        logger.info(f'COVID Backend Server running on {addr}')
        
        async with server:
            await server.serve_forever()
            
    async def maintenance_task(self):
        """Regular maintenance tasks"""
        while True:

            # Log statistics
            logger.info(f"Server stats: {self.stats}")
            
            # Wait before next maintenance
            await asyncio.sleep(60)  # 1 min
            
    async def run(self):
        """Run the server with all tasks"""
        await asyncio.gather(
            self.run_server(),
            self.maintenance_task()
        )

if __name__ == "__main__":
    # Parse command line arguments (if needed)
    import argparse
    parser = argparse.ArgumentParser(description='COVID-19 Contact Tracing Backend Server')
    parser.add_argument('--host', type=str, default='0.0.0.0', help='Host to bind')
    parser.add_argument('--port', type=int, default=55000, help='Port to listen on')
    parser.add_argument('--retention', type=int, default=14, help='CBF retention days')
    
    args = parser.parse_args()
    
    # Create and run server
    server = COVIDBackendServer(args.host, args.port, args.retention)
    
    try:
        asyncio.run(server.run())
    except KeyboardInterrupt:
        logger.info("Server shutdown requested")
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
    finally:
        logger.info("Server shutdown complete")