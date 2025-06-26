#!/usr/bin/env python3
"""
BloomFilter.py

This module implements a basic Bloom filter.
It creates a bit array of a specified size and uses multiple hash functions (using mmh3)
to map inserted items to bit positions. This filter supports insertion, membership checking,
combining with another filter, and a simple overlap/match check.
"""

from bitarray import bitarray
import mmh3

class BloomFilter:
    def __init__(self,size_bits=800_000, hash_count=3):
        """
        Initialize the Bloom Filter.
        
        Args:
            size_bits: The no. of buts in the filter (default: 800000 bits for 100KB)
            hash_count: The no. of hash functions(default: 3)
        """
        self.size = size_bits
        self.hash_count = hash_count
        # Initialize the bitarray with all bits set to 0.
        self.bitarray = bitarray(size_bits)
        self.element_count = 0
        self.bitarray.setall(0)
        self.bit_count = 0

    def add(self, item):
        """
        Inserts an an item into the Bloom Filter.
        
         Args:
            item (str or bytes): The element to be added
        """
        for i in range(self.hash_count):
            index = mmh3.hash(item,i) % self.size
            if not self.bitarray[index]:
                self.bit_count += 1
            self.bitarray[index] = True
        self.element_count += 1

    def __iadd__(self,item):
        """Overloads the '+=' operator to insert an item."""
        self.add(item)
        return self

    def __contains__(self, item):
        """
        Checks if an item is possibly in the Bloom Filter.
        Returns:
            bool: True if the item is possibly in the filter, False if definitely not.
        """
        for i in range(self.hash_count):
            index = mmh3.hash(item,i) % self.size
            if not self.bitarray[index]:
                return False
        return True
    
    def combine(self, other):
        """
        Merges another Bloom Filter using bitwise OR
        
        Args:
            other (BloomFilter): Another Bloom Filter to combine with.
        Raises:
            AssertionError: If the two filters do not have the same size or number
        """
        assert self.size == other.size, "Bloom Filters must have the same size to combine."
        assert self.hash_count == other.hash_count, "Bloom Filters must have the same hash count to combine."
        self.bitarray |= other.bitarray
        self.element_count += other.element_count
        self.bit_count = self.bitarray.count(True)
    
    def match(self, other, threshold=3):
        """
        Checks if this filter and another have at least `threshold` bits in common.
        
        Args:
            other (BloomFilter): Another Bloom filter to compare.
            threshold (int): Minimum number of overlapping bits to consider as a match.
        
        Returns:
            bool: True if the number of overlapping bits is >= threshold; otherwise, False.
        """
        assert self.size == other.size, "Bloom filters must have the same size."
        assert self.hash_count == other.hash_count, "Bloom filters must have the same hash count."
        common = (self.bitarray & other.bitarray).count(True)
        return common >= threshold

    def __len__(self):
        """Returns the number of items added to the filter."""
        return self.element_count

    def __str__(self):
        """Returns a string listing indices with True values."""
        return str([i for i, bit in enumerate(self.bitarray) if bit])

    def copy(self):
        """
        Return a deep copy of the Bloom Filter.
        """
        new_bf = BloomFilter(self.size, self.hash_count)
        new_bf.bitarray = self.bitarray.copy()
        new_bf.element_count = self.element_count
        return new_bf
    
    def to_bytes(self):
        """Convert the bloom filter to bytes for transmission"""
        # Return the bitarray as bytes
        return self.bitarray.tobytes()

    @classmethod
    def from_bytes(cls, data):
        """Create a BloomFilter from bytes"""
        # Create a new empty filter
        bf = cls()  # Adapt as needed
        
        # Load data into bitarray
        bf.bitarray = bitarray()
        bf.bitarray.frombytes(data)
        
        return bf

    def has_intersection(self, other):
        """
        Check if this BloomFilter has intersection with another
        Returns True if there's a potential match, False otherwise
        """
        # Create temporary copy of both bitarrays
        a = self.bitarray.copy()
        b = other.bitarray.copy()
        
        # Perform bitwise AND
        a &= b
        
        # If any bit is set in the result, there's an intersection
        return a.any()

# Basic Test/Demo
# if __name__ == '__main__':
#     bf = BloomFilter()
#     bf.add("apple")
#     bf += "banana"

#     assert "apple" in bf
#     assert "banana" in bf
#     assert "pear" not in bf

#     assert len(bf) == 2
#     assert bf.bitarray.count(True) == 6  # For two items with 3 hashes each.

#     bf += "pear"
#     assert "pear" in bf

#     bf2 = BloomFilter()
#     bf2.add("orange")
    
#     # Test combining filters.
#     bf.combine(bf2)
#     assert "orange" in bf

#     print("BloomFilter module tests passed.")