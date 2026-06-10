import struct
import hashlib
from dataclasses import dataclass, field

from ipv8.messaging.payload_dataclass import VariablePayload, vp_compile
from ipv8.community import Community, CommunitySettings
from ipv8.lazy_community import Peer, lazy_wrapper
from ipv8.peerdiscovery.network import PeerObserver



@dataclass
class Transaction:
    sender_key: bytes
    data: bytes
    timestamp: int
    signature: bytes

    @property
    def hash(self) -> bytes:
        return hashlib.sha256(
            self.sender_key + self.data + struct.pack(">q", self.timestamp) + self.signature
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
    transactions: list[Transaction] = field(default_factory=list)

def genesis_block() -> Block:
    prev_hash = bytes(32)          # no parent
    transactions = []
    txs_hash = compute_txs_hash([])  # SHA256(b"")
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
        transactions=transactions,
    )

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

def compute_txs_hash(tx_hashes: list[bytes]) -> bytes:
    return hashlib.sha256(b"".join(tx_hashes)).digest()

class BlockchainCommunity(Community, PeerObserver):
    community_id = b""  # set at runtime from .env
    
    def __init__(self, settings: CommunitySettings) -> None:
        super().__init__(settings)
        self.chain: list[Block] = [genesis_block()]
        self.mempool: list[Transaction] = []
        self.add_message_handler(SubmitTransaction, self.on_submit_transaction)
        self.add_message_handler(GetChainHeight, self.on_get_chain_height)
        self.add_message_handler(GetBlock, self.on_get_block)

    @lazy_wrapper(GetBlock)
    def on_get_block(self, peer: Peer, msg: GetBlock) -> None:
        if msg.height < 0 or msg.height >= len(self.chain):
            return
        block = self.chain[msg.height]
        tx_hashes = b"".join(tx.hash for tx in block.transactions)
        self.ez_send(peer, BlockResponse(
            height=block.height,
            prev_hash=block.prev_hash,
            txs_hash=block.txs_hash,
            timestamp=block.timestamp,
            difficulty=block.difficulty,
            nonce=block.nonce,
            block_hash=block.hash,
            tx_hashes=tx_hashes,
        ))
        
    @lazy_wrapper(SubmitTransaction)
    def on_submit_transaction(self, peer: Peer, msg: SubmitTransaction) -> None:
        # Reconstruct and verify the signature
        try:
            public_key = self.crypto.key_from_public_bin(msg.sender_key)
            signing_payload = msg.data + struct.pack(">q", msg.timestamp)
            public_key.verify(msg.signature, signing_payload)
        except Exception as e:
            self.ez_send(peer, SubmitTransactionResponse(
                success=False,
                tx_hash=b"",
                message=f"Invalid signature: {e}",
            ))
            return

        # Build the Transaction object
        tx = Transaction(
            sender_key=msg.sender_key,
            data=msg.data,
            timestamp=msg.timestamp,
            signature=msg.signature,
        )

        # Check for duplicates
        tx_hash = tx.hash
        if any(t.hash == tx_hash for t in self.mempool):
            self.ez_send(peer, SubmitTransactionResponse(
                success=False,
                tx_hash=tx_hash,
                message="Transaction already in mempool",
            ))
            return

        # Add to mempool and respond
        self.mempool.append(tx)
        self.ez_send(peer, SubmitTransactionResponse(
            success=True,
            tx_hash=tx_hash,
            message="Transaction accepted",
        ))

    @lazy_wrapper(GetChainHeight)
    def on_get_chain_heigt(self, peer: Peer, msg: GetChainHeight):
        tip = self.chain[-1]
        self.ez_send(peer, ChainHeightResponse(
            request_id=msg.request_id,
            height=len(self.chain) - 1,
            tip_hash=tip.hash,
        ))
    #   reply with ChainHeightResponse(request_id, len(chain)-1, chain[-1].hash)