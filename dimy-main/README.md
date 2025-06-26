#  DIMY Protocol — "Did I Meet You?"

University of New South Wales  
COMP4337/9337 — Securing Fixed and Wireless Networks  
Term 1, 2025

## Team Members
- **Divya Tyagi** — z5514961  
- **Haithm Ezzaddin** — z5482376  
- **Lab Session:** H11A

---

## Running the Code

1. **Dependencies**
```sh
 pip install -r requirements.txt
```
2. **Start the backend server**
```
python3 DimyServer.py --port 55000
```
3. **Run a DIMY node (client) in a new terminal:**
```
python3 Dimy.py 15 3 5
```
4. **Run an attacker node in another terminal:**
```
python3 Attacker.py 12345 3 5
```

##  Tasks Implemented

All Tasks 1–11 from the assignment specification are implemented:

| Task | Description |
|------|-------------|
| 1    | EphID generation every *t* seconds using X25519 |
| 2    | k-out-of-n Shamir Secret Sharing for EphIDs |
| 3    | UDP broadcasting of shares every 3s |
| 3a   | 50% message drop simulation |
| 4    | EphID reconstruction with optional hash verification |
| 5    | Diffie-Hellman-based EncID generation |
| 6    | Bloom filter insertion of EncIDs |
| 7    | DBF rotation and expiry after *(t × 6 × 6)/60* minutes |
| 8    | QBF creation from DBFs |
| 9    | CBF upload to server via TCP |
| 10   | QBF query to server with threshold matching |
| 11A  | security mechanism employed in the DIMY protocol (theoretical) |
| 11B  | Forged Share Attack via Attacker node |
| 11C  | TCP Replay Attack (theoretical) |
| 11D  | Defense measures for attacks |

---


## References
- [bitarray](https://pypi.org/project/bitarray/)
- [mmh3](https://pypi.org/project/mmh3/)
- [pycryptodome](https://pypi.org/project/pycryptodome/)
- [subrosa](https://pypi.org/project/subrosa/)
- [requirements.txt](./requirements.txt)
- [StackOverflow](https://stackoverflow.com/questions/55457370/how-to-avoid-valueerror-separator-is-not-found-and-chunk-exceed-the-limit)