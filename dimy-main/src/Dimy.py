#!/usr/bin/env python3
import argparse
import asyncio
from secretSharingBroadcaster import DistributedSecretSharing


def validate_args():
    parser = argparse.ArgumentParser(description="Validate three input values: t, k, and n.")
    parser.add_argument("t", type=int, help="Value of t (must be one of {15, 18, 21, 24, 27, 30})")
    parser.add_argument("k", type=int, help="Value of k (must be at least 3)")
    parser.add_argument("n", type=int, help="Value of n (must be at least 5 and greater than k)")
    
    args = parser.parse_args()
    
    valid_t_values = {15, 18, 21, 24, 27, 30}
    if args.t not in valid_t_values:
        raise ValueError(f"Error: t must be one of {valid_t_values}. Received: {args.t}")
    if args.k * 3 > args.t:
        raise ValueError(f"Error: should be 3k <= t")
    if args.k < 3:
        raise ValueError("Error: k must be at least 3.")
    # if 32 % args.n != 0:
    #     raise ValueError("Error: 32 must be divisible by n.")
    if args.n < 5:
        raise ValueError("Error: n must be at least 5.")
    if args.k >= args.n:
        raise ValueError("Error: k must be less than n.")
    
    return args.t, args.k, args.n

async def main(t, k, n):
    # Create and run the distributed secret sharing node
    node = DistributedSecretSharing(t, k, n)
    await node.run()

if __name__ == "__main__":
    try:
        t, k, n = validate_args()
    except ValueError as e:
        print(e)
        exit(1)

    try:
        asyncio.run(main(t, k, n))
    except KeyboardInterrupt:
        print("\nInterrupted. Exiting gracefully.")
        exit(0)

    
