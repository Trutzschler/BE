import asyncio
import struct
import time

from ipv8.messaging.payload_dataclass import VariablePayload, vp_compile
from ipv8.community import Community, CommunitySettings
from ipv8.lazy_community import Peer, lazy_wrapper
from ipv8.peerdiscovery.network import PeerObserver

from chain import (
    Block,
    Transaction,
    compute_txs_hash,
    genesis_block,
    search_nonce,
    split_tx_hashes,
    validate_block,
)

# PoW difficulty (leading zero bits)
MINING_DIFFICULTY = 17
# Nonces tried per batch
MINING_BATCH = 20000
# Brief pause after a block to allow for propegation
INTER_BLOCK_PAUSE = 0.1


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
        self._mining: bool = False
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

    def start_mining(self) -> None:
        if self._mining:
            return
        self._mining = True
        self.register_task("mining", self.mining_loop)

    async def mining_loop(self) -> None:
        while self._mining:
            block = await self._mine_candidate()
            if block is not None and self.add_block(block):
                self.broadcast_block(block)
                await asyncio.sleep(INTER_BLOCK_PAUSE)

    async def _mine_candidate(self) -> Block | None:
        """Grind nonces on the current tip in batches, abandoning a stale candidate."""
        prev_hash = self.tip_hash
        height = self.tip.height + 1
        version = self.mempool_version
        tx_hashes = [tx.hash for tx in self.pending_txs()]
        txs_hash = compute_txs_hash(tx_hashes)
        timestamp = int(time.time())
        nonce = 0
        while self._mining:
            found = search_nonce(
                prev_hash, txs_hash, timestamp, MINING_DIFFICULTY, nonce, MINING_BATCH
            )
            if found is not None:
                nonce, h = found
                return Block(
                    height=height,
                    prev_hash=prev_hash,
                    txs_hash=txs_hash,
                    timestamp=timestamp,
                    difficulty=MINING_DIFFICULTY,
                    nonce=nonce,
                    hash=h,
                    tx_hashes=tx_hashes,
                )
            nonce += MINING_BATCH
            await asyncio.sleep(0)
            if self.tip_hash != prev_hash or self.mempool_version != version:
                return None

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
