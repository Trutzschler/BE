import hashlib
import struct
import time
import multiprocessing as mp

def worker(email: str, github_url: str, start_nonce: int, step: int, result_queue: mp.Queue):
    """Each worker checks every `step`-th nonce starting from start_nonce."""
    prefix = email.encode("utf-8") + b"\n" + github_url.encode("utf-8") + b"\n"
    nonce = start_nonce

    while True:
        nonce_bytes = struct.pack(">q", nonce)
        digest = hashlib.sha256(prefix + nonce_bytes).digest()

        if digest[0] == 0 and digest[1] == 0 and digest[2] == 0 and digest[3] < 0x10:
            result_queue.put(nonce)
            return

        nonce += step

def mine(email: str, github_url: str) -> int:
    num_cores = mp.cpu_count()
    print(f"Mining with {num_cores} cores...")

    result_queue = mp.Queue()
    processes = []

    start = time.time()

    # Each worker starts at a different nonce and jumps by num_cores
    # so they never check the same nonce twice
    for i in range(num_cores):
        p = mp.Process(target=worker, args=(email, github_url, i, num_cores, result_queue))
        p.start()
        processes.append(p)

    # Wait for the first worker to find a solution
    nonce = result_queue.get()

    # Kill all other workers
    for p in processes:
        p.terminate()
        p.join()

    elapsed = time.time() - start
    print(f"Found nonce: {nonce} in {elapsed:.1f}s")

    # Verify it locally
    prefix = email.encode("utf-8") + b"\n" + github_url.encode("utf-8") + b"\n"
    digest = hashlib.sha256(prefix + struct.pack(">q", nonce)).digest()
    print(f"Hash: {digest.hex()}")
    print(f"Leading zero bits verified: {digest[:4].hex()}")

    return nonce

if __name__ == "__main__":
    email = "m.a.trutzschlervonfalkenstein@student.tudelft.nl"
    github_url = "https://github.com/Trutzschler/BE"

    nonce = mine(email, github_url)

    print(f"\nNonce found: {nonce}")

