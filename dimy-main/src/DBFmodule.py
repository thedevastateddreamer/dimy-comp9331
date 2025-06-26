#!/usr/bin/env python3
"""
dbf_module.py

This module manages the Daily Bloom Filter (DBF) and its rotation.
Each DBF stores the Encounter IDs (EncIDs) for a specific time window.
A new DBF is created every (t * 6) seconds, and at most 6 DBFs are retained.
DBFs older than the retention period (Dt = (t * 6 * 6) / 60 minutes, converted to seconds)
are automatically purged.
"""

import time
import uuid
from BloomFilter import BloomFilter 
from Crypto.Hash import SHA256

class DailyBloomFilter:
    def __init__(self, size_bits=800000, hash_count=3):
        """
        Initialize a Daily Bloom Filter (DBF)

        Args:
            size_bits (int): Size of the Bloom Filter in bits (default 800,000 bits for 100KB)
            hash_count (int): Number of hash functions (default 3)
        """
        self.bloom_filter = BloomFilter(size_bits, hash_count)
        self.timestamp = time.time() 
        self.bloom_filter_id = str(uuid.uuid4())

    def add_encid(self, encid):
        """
        Adds an Encounter ID (EncID) into the Bloom filter.
        
        Args:
            encid (bytes): A 32-byte Encounter ID.
        """
        self.bloom_filter.add(encid)
        print(f"Encoded EncID into Bloomfilter ID {self.bloom_filter_id[0:8]}..., Hash of filter: {SHA256.new(self.bloom_filter.to_bytes()).hexdigest()[0:8]}...")

class DBFCache:
    def __init__(self, t, max_dbfs=6):
        """
        Manage a cache of Daily Bloom Filters (DBFs).
        
        Args:
            t (int): The base time parameter (in seconds) from the command-line argument.
                     Each DBF covers t*6 seconds.
            max_dbfs (int): Maximum number of DBFs to retain (default 6).
        """
        self.t = t
        self.period = t * 6  # Time window for each DBF in seconds
        # Retention time in seconds: Dt = (t * 6 * 6) / 60 minutes, converted to seconds.
        self.dbf_retention = ((t * 6 * 6) / 60) * 60  
        self.max_dbfs = max_dbfs
        self.dbfs = []
        # Start with an initial DBF.
        self.current_dbf = DailyBloomFilter()
        self.dbfs.append(self.current_dbf)
    
    def add_encid(self, encid):
        """
       Adds a 32-byte EncID to the current DBF.
        Rotates the DBF if the time window has expired and removes old DBFs if necessary.

        Args:
            encid (bytes): The Encounter ID to add.
        """
        current_time = time.time()
        # If the time window (t*6 seconds) is over, create a new DBF.
        if current_time - self.current_dbf.timestamp >= self.period:
            self.current_dbf = DailyBloomFilter()
            self.dbfs.append(self.current_dbf)
            print(f"New Bloomfilter Created, ID: {self.current_dbf.bloom_filter_id[0:8]}...")
            
            self.clean_old_dbfs()
        # Insert the EncID into the current DBF.
        self.current_dbf.add_encid(encid)
        
    
    def clean_old_dbfs(self):
        """
        Remove DBFs that exceed the retention duration or exceed the maximum stored count.
        """
        current_time = time.time()
        # Filter out DBFs older than the retention period.
        self.dbfs = [dbf for dbf in self.dbfs if current_time - dbf.timestamp <= self.dbf_retention]
        # Ensure we have at most max_dbfs stored.
        while len(self.dbfs) > self.max_dbfs:
            self.dbfs.pop(0)

        print("One Bloomfilter has reached time expiry or max capacity, deleting...")
    
    def combine_dbfs(self):
        """
        Combines all stored DBFs into a single Bloom filter.
        This is typically used to create a Query Bloom Filter (QBF).

        Returns:
            BloomFilter: A Bloom filter that represents the bitwise OR of all current DBFs.
        """
        if not self.dbfs:
            return None
        combined = self.dbfs[0].bloom_filter.copy()  
        # Bitwise OR each subsequent DBF into the combined filter.
        for dbf in self.dbfs[1:]:
            combined.combine(dbf.bloom_filter)  # Assuming the internal data is in 'bitarray'
        return combined

# # For testing the DBF module.
# if __name__ == "__main__":
#     t = 15  # Example parameter
#     dbf_cache = DBFCache(t)
    
#     # Simulate adding a dummy EncID (32 bytes).
#     dummy_encid = b'\xAA' * 32
#     dbf_cache.add_encid(dummy_encid)
    
#     print(f"Number of DBFs after one insert: {len(dbf_cache.dbfs)}")
#     print("Combined Bloom filter bit count (approx):", dbf_cache.combine_dbfs().bitarray.count(True))
    