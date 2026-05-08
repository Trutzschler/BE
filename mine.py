import hashlib
import multiprocessing
import random
import struct

def mine(prefix: bytes, difficulty: float) -> bytes:
    target = compute_target(difficulty)

    result = multiprocessing.Queue()
    stop = multiprocessing.Event()

    cpu_count = multiprocessing.cpu_count()
    print(f"Mining on {cpu_count} cores")

    procs  = [
        multiprocessing.Process(target=run_worker, args=(prefix, target, result, stop), daemon=True)
        for _ in range(cpu_count)
    ]
    for p in procs:
        p.start()

    nonce = result.get()

    for p in procs:
        p.terminate()

    return nonce

def run_worker(prefix: bytes, target: bytes, result, stop) -> None:
    while not stop.is_set():
        nonce = struct.pack(">q", random.getrandbits(63))
        if verify_nonce(prefix, target, nonce):
            result.put(nonce)
            stop.set()

def verify_nonce(prefix: bytes, target: bytes, nonce: bytes) -> bool:
    data = prefix + nonce
    return hashlib.sha256(data).digest() <= target

def compute_target(difficulty: int) -> bytes:
    return (int(2 ** (256 - difficulty)) - 1).to_bytes(32)

def nonce_byte_to_int(nonce: bytes) -> int:
    return struct.unpack(">q", nonce)[0]