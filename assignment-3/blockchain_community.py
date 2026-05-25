import struct
import hashlib

from ipv8.messaging.payload_dataclass import VariablePayload, vp_compile

@vp_compile
class SubmitTransaction(VariablePayload):
    msg_id = 1
    format_list = ["varlenH", "varlenH", "q", "varlenH"]
    names = ["sender_key", "data", "timestamp", "signature"]

@vp_compile
class SubmitTransactionResponse(VariablePayload):
    msg_id = 2
    format_list = ["?", "varlenH", "varlenHutf8"]
    names = ["success", "tx_hash", "message"]

@vp_compile
class GetChainHeight(VariablePayload):
    msg_id = 3
    format_list = ["q"]
    names = ["request_id"]

@vp_compile
class ChainHeightResponse(VariablePayload):
    msg_id = 4
    format_list = ["q", "q", "varlenH"]
    names = ["request_id", "height", "tip_hash"]

@vp_compile
class GetBlock(VariablePayload):
    msg_id = 5
    format_list = ["q"]
    names = ["height"]

@vp_compile
class BlockResponse(VariablePayload):
    msg_id = 6
    format_list = ["q", "varlenH", "varlenH", "q", "q", "q", "varlenH", "varlenH"]
    names = ["height", "prev_hash", "txs_hash", "timestamp", "difficulty", "nonce", "block_hash", "tx_hashes"]

def pack_header(prev_hash, txs_hash, timestamp, difficulty, nonce) -> bytes:
    return (
        prev_hash                           # 32 bytes
        + txs_hash                          # 32 bytes
        + struct.pack(">Q", timestamp)      # 8 bytes, uint64 big-endian
        + struct.pack(">I", difficulty)     # 4 bytes, uint32 big-endian
        + struct.pack(">Q", nonce)          # 8 bytes, uint64 big-endian
    )

def block_hash(header: bytes) -> bytes:
    return hashlib.sha256(header).digest()

def meets_difficulty(hash_bytes: bytes, difficulty: int) -> bool:
    value = int.from_bytes(hash_bytes, "big")
    return value >> (256 - difficulty) == 0 # check if leading bits are 0s

def mine(prev_hash, txs_hash, timestamp, difficulty) -> tuple[int, bytes]:
    nonce = 0
    while True:
        header = pack_header(prev_hash, txs_hash, timestamp, difficulty, nonce)
        h = block_hash(header)
        if meets_difficulty(h, difficulty):
            return nonce, h
        nonce += 1
