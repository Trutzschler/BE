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
    names = [
        "height",
        "prev_hash",
        "txs_hash",
        "timestamp",
        "difficulty",
        "nonce",
        "block_hash",
        "tx_hashes",
    ]


# Internal gossip between the 3 group nodes (ids >= 7, not used by the server).
_BLOCK_FORMAT = ["q", "varlenH", "varlenH", "q", "q", "q", "varlenH", "varlenH"]
_BLOCK_NAMES = [
    "height",
    "prev_hash",
    "txs_hash",
    "timestamp",
    "difficulty",
    "nonce",
    "block_hash",
    "tx_hashes",
]


@vp_compile
class NewBlock(VariablePayload):
    msg_id = 7
    format_list = _BLOCK_FORMAT
    names = _BLOCK_NAMES


@vp_compile
class NewTransaction(VariablePayload):
    msg_id = 8
    format_list = ["varlenH", "varlenH", "q", "varlenH"]
    names = ["sender_key", "data", "timestamp", "signature"]


@vp_compile
class GetBlockByHash(VariablePayload):
    msg_id = 9
    format_list = ["varlenH"]
    names = ["block_hash"]


@vp_compile
class BlockByHash(VariablePayload):
    msg_id = 10
    format_list = _BLOCK_FORMAT
    names = _BLOCK_NAMES


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


class BlockchainCommunity(Community, PeerObserver):
    community_id = b""  # set at runtime from .env

    def __init__(self, settings: CommunitySettings) -> None:
        super().__init__(settings)
        genesis = genesis_block()
        self.blocks: dict[bytes, Block] = {genesis.hash: genesis}
        self.tip_hash: bytes = genesis.hash
        self.canonical: list[Block] = [genesis]
        self.included: set[bytes] = set()
        self.txpool: dict[bytes, Transaction] = {}
        self.orphans: dict[bytes, Block] = {}
        self.mempool_version: int = 0
        self.teammates: set[bytes] = set()
        self.add_message_handler(SubmitTransaction, self.on_submit_transaction)
        self.add_message_handler(GetChainHeight, self.on_get_chain_height)
        self.add_message_handler(GetBlock, self.on_get_block)
        self.add_message_handler(NewBlock, self.on_new_block)
        self.add_message_handler(NewTransaction, self.on_new_transaction)
        self.add_message_handler(GetBlockByHash, self.on_get_block_by_hash)
        self.add_message_handler(BlockByHash, self.on_block_by_hash)

    @property
    def tip(self) -> Block:
        return self.blocks[self.tip_hash]

    @property
    def height(self) -> int:
        return self.tip.height

    def pending_txs(self) -> list[Transaction]:
        return [tx for h, tx in self.txpool.items() if h not in self.included]

    def add_tx(self, tx: Transaction) -> bool:
        """Record a full transaction. Returns True if it was new."""
        if tx.hash in self.txpool:
            return False
        self.txpool[tx.hash] = tx
        self.mempool_version += 1
        return True

    def add_block(self, block: Block) -> bool:
        """Link a validated block to a known parent and refresh the canonical chain."""
        if block.hash in self.blocks:
            return False
        parent = self.blocks.get(block.prev_hash)
        if parent is None:
            self.orphans[block.prev_hash] = block
            return False
        if block.height != parent.height + 1:
            return False
        self.blocks[block.hash] = block
        self._attach_orphans(block.hash)
        self._recompute_tip()
        return True

    def _attach_orphans(self, parent_hash: bytes) -> None:
        orphan = self.orphans.pop(parent_hash, None)
        if orphan is None:
            return
        if orphan.height == self.blocks[parent_hash].height + 1:
            self.blocks[orphan.hash] = orphan
            self._attach_orphans(orphan.hash)

    def _recompute_tip(self) -> None:
        best = self.blocks[self.tip_hash]
        for b in self.blocks.values():
            if b.height > best.height or (
                b.height == best.height and b.hash < best.hash
            ):
                best = b
        if best.hash != self.tip_hash:
            self.tip_hash = best.hash
            self._rebuild_canonical()

    def _rebuild_canonical(self) -> None:
        chain: list[Block] = []
        h = self.tip_hash
        while True:
            b = self.blocks[h]
            chain.append(b)
            if b.height == 0:
                break
            h = b.prev_hash
        chain.reverse()
        self.canonical = chain
        self.included = {tx for b in chain for tx in b.tx_hashes}
        self.mempool_version += 1

    def _teammate_peers(self) -> list[Peer]:
        return [
            p for p in self.get_peers() if p.public_key.key_to_bin() in self.teammates
        ]

    def _is_teammate(self, peer: Peer) -> bool:
        return peer.public_key.key_to_bin() in self.teammates

    def _block_kwargs(self, block: Block) -> dict:
        return {
            "height": block.height,
            "prev_hash": block.prev_hash,
            "txs_hash": block.txs_hash,
            "timestamp": block.timestamp,
            "difficulty": block.difficulty,
            "nonce": block.nonce,
            "block_hash": block.hash,
            "tx_hashes": b"".join(block.tx_hashes),
        }

    def _block_from_wire(self, msg) -> Block:
        return Block(
            height=msg.height,
            prev_hash=msg.prev_hash,
            txs_hash=msg.txs_hash,
            timestamp=msg.timestamp,
            difficulty=msg.difficulty,
            nonce=msg.nonce,
            hash=msg.block_hash,
            tx_hashes=split_tx_hashes(msg.tx_hashes),
        )

    def broadcast_block(self, block: Block) -> None:
        payload = NewBlock(**self._block_kwargs(block))
        for peer in self._teammate_peers():
            self.ez_send(peer, payload)

    def broadcast_tx(self, tx: Transaction) -> None:
        payload = NewTransaction(tx.sender_key, tx.data, tx.timestamp, tx.signature)
        for peer in self._teammate_peers():
            self.ez_send(peer, payload)

    def _verify_tx(self, sender_key, data, timestamp, signature) -> bool:
        try:
            public_key = self.crypto.key_from_public_bin(sender_key)
            payload = sender_key + data + struct.pack(">q", timestamp)
            public_key.verify(signature, payload)
            return True
        except Exception:
            return False

    def integrate_block(self, block: Block, source: Peer | None = None) -> None:
        """Validate, link, and re-flood a block; pull its parent if it is an orphan."""
        if block.hash in self.blocks or not validate_block(block):
            return
        had_parent = block.prev_hash in self.blocks
        if self.add_block(block):
            self.broadcast_block(block)
        elif not had_parent and source is not None:
            self.ez_send(source, GetBlockByHash(block_hash=block.prev_hash))

    @lazy_wrapper(GetBlock)
    def on_get_block(self, peer: Peer, msg: GetBlock) -> None:
        if msg.height < 0 or msg.height >= len(self.canonical):
            return
        block = self.canonical[msg.height]
        tx_hashes = b"".join(block.tx_hashes)
        self.ez_send(
            peer,
            BlockResponse(
                height=block.height,
                prev_hash=block.prev_hash,
                txs_hash=block.txs_hash,
                timestamp=block.timestamp,
                difficulty=block.difficulty,
                nonce=block.nonce,
                block_hash=block.hash,
                tx_hashes=tx_hashes,
            ),
        )

    @lazy_wrapper(SubmitTransaction)
    def on_submit_transaction(self, peer: Peer, msg: SubmitTransaction) -> None:
        if not self._verify_tx(msg.sender_key, msg.data, msg.timestamp, msg.signature):
            self.ez_send(
                peer,
                SubmitTransactionResponse(
                    success=False,
                    tx_hash=b"",
                    message="Invalid signature",
                ),
            )
            return

        tx = Transaction(
            sender_key=msg.sender_key,
            data=msg.data,
            timestamp=msg.timestamp,
            signature=msg.signature,
        )
        if self.add_tx(tx):
            self.broadcast_tx(tx)
        self.ez_send(
            peer,
            SubmitTransactionResponse(
                success=True,
                tx_hash=tx.hash,
                message="Transaction accepted",
            ),
        )

    @lazy_wrapper(GetChainHeight)
    def on_get_chain_height(self, peer: Peer, msg: GetChainHeight) -> None:
        self.ez_send(
            peer,
            ChainHeightResponse(
                request_id=msg.request_id,
                height=self.height,
                tip_hash=self.tip_hash,
            ),
        )

    @lazy_wrapper(NewBlock)
    def on_new_block(self, peer: Peer, msg: NewBlock) -> None:
        if not self._is_teammate(peer):
            return
        self.integrate_block(self._block_from_wire(msg), source=peer)

    @lazy_wrapper(NewTransaction)
    def on_new_transaction(self, peer: Peer, msg: NewTransaction) -> None:
        if not self._is_teammate(peer):
            return
        if not self._verify_tx(msg.sender_key, msg.data, msg.timestamp, msg.signature):
            return
        tx = Transaction(msg.sender_key, msg.data, msg.timestamp, msg.signature)
        if self.add_tx(tx):
            self.broadcast_tx(tx)

    @lazy_wrapper(GetBlockByHash)
    def on_get_block_by_hash(self, peer: Peer, msg: GetBlockByHash) -> None:
        if not self._is_teammate(peer):
            return
        block = self.blocks.get(msg.block_hash)
        if block is not None:
            self.ez_send(peer, BlockByHash(**self._block_kwargs(block)))

    @lazy_wrapper(BlockByHash)
    def on_block_by_hash(self, peer: Peer, msg: BlockByHash) -> None:
        if not self._is_teammate(peer):
            return
        self.integrate_block(self._block_from_wire(msg), source=peer)
