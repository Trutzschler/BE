import struct
import hashlib
from dataclasses import dataclass, field


@dataclass
class Transaction:
    sender_key: bytes
    data: bytes
    timestamp: int
    signature: bytes

    @property
    def hash(self) -> bytes:
        return hashlib.sha256(
            self.sender_key
            + self.data
            + struct.pack(">q", self.timestamp)
            + self.signature
        ).digest()


@dataclass
class Block:
    height: int
    prev_hash: bytes
    txs_hash: bytes
    timestamp: int
    difficulty: int
    nonce: int
    hash: bytes
    tx_hashes: list[bytes] = field(default_factory=list)


def pack_header(prev_hash, txs_hash, timestamp, difficulty, nonce) -> bytes:
    return (
        prev_hash  # 32 bytes
        + txs_hash  # 32 bytes
        + struct.pack(">Q", timestamp)  # 8 bytes, uint64 big-endian
        + struct.pack(">I", difficulty)  # 4 bytes, uint32 big-endian
        + struct.pack(">Q", nonce)  # 8 bytes, uint64 big-endian
    )


def block_hash(header: bytes) -> bytes:
    return hashlib.sha256(header).digest()


def meets_difficulty(hash_bytes: bytes, difficulty: int) -> bool:
    value = int.from_bytes(hash_bytes, "big")
    return value >> (256 - difficulty) == 0  # check if leading bits are 0s


def mine(prev_hash, txs_hash, timestamp, difficulty) -> tuple[int, bytes]:
    nonce = 0
    while True:
        header = pack_header(prev_hash, txs_hash, timestamp, difficulty, nonce)
        h = block_hash(header)
        if meets_difficulty(h, difficulty):
            return nonce, h
        nonce += 1


def search_nonce(
    prev_hash, txs_hash, timestamp, difficulty, start_nonce, rounds
) -> tuple[int, bytes] | None:
    """Try rounds nonces from start_nonce. Return (nonce, hash) on a hit, else None."""
    nonce = start_nonce
    for _ in range(rounds):
        header = pack_header(prev_hash, txs_hash, timestamp, difficulty, nonce)
        h = block_hash(header)
        if meets_difficulty(h, difficulty):
            return nonce, h
        nonce += 1
    return None


def compute_txs_hash(tx_hashes: list[bytes]) -> bytes:
    return hashlib.sha256(b"".join(tx_hashes)).digest()


def split_tx_hashes(blob: bytes) -> list[bytes]:
    return [blob[i : i + 32] for i in range(0, len(blob), 32)]


def validate_block(block: Block) -> bool:
    """Self-consistency: header hashes to its claimed hash, PoW holds, body commits."""
    header = pack_header(
        block.prev_hash, block.txs_hash, block.timestamp, block.difficulty, block.nonce
    )
    if block_hash(header) != block.hash:
        return False
    if not meets_difficulty(block.hash, block.difficulty):
        return False
    return compute_txs_hash(block.tx_hashes) == block.txs_hash


def genesis_block() -> Block:
    prev_hash = bytes(32)
    txs_hash = compute_txs_hash([])
    timestamp = 0
    difficulty = 1
    nonce, h = mine(prev_hash, txs_hash, timestamp, difficulty)
    return Block(
        height=0,
        prev_hash=prev_hash,
        txs_hash=txs_hash,
        timestamp=timestamp,
        difficulty=difficulty,
        nonce=nonce,
        hash=h,
        tx_hashes=[],
    )
