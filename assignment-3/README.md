# Lab 3 - PoW Blockchain

Three nodes run a shared Proof-of-Work chain over IPv8. They mine, gossip blocks, and converge on one chain by the longest-chain rule. The Lab 3 server joins the chain, submits a test transaction, and checks PoW, linking, body commitment, and that all three nodes agree.

## Files

- `chain.py` - block/transaction model and pure PoW (hashing, nonce search). No networking.
- `blockchain_community.py` - the overlay: block store, fork choice, gossip, mining loop.
- `registration_community.py` - registers our chain with the Lab 3 server.
- `main.py` - runs both overlays in one process and never exits.

## Design choices

- **All three nodes mine.** Forks are resolved by longest chain, with a smaller-hash tie-break so every node picks the same winner.
- **Fork-aware store.** Blocks are kept by hash, not in a standard list. A block whose parent is missing is held as an orphan and the parent is pulled with `GetBlockByHash`. This is also how a node catches up after dropped packets.
- **Tip heartbeat.** Every node re-announces its tip every few seconds, so a node that missed a block backfills the gap instead of staying behind.
- **One smart registrar.** Only the lowest-pubkey member registers, and only once all three nodes are actually online. It keeps re-registering until we pass. `FORCE_REGISTER=1` overrides this.
- **Mining yields.** The nonce search runs in batches and gives the event loop a turn between them, so mining never blocks message handling.

## Messages we added

The server defines messages 1–6. Everything our nodes need to talk to each other we added as ids 7–10, so they never clash with the server protocol:

- `NewBlock` (7) - flood a freshly mined or received block to teammates.
- `NewTransaction` (8) - flood a transaction so every mempool has it.
- `GetBlockByHash` (9) - ask a teammate for a block we're missing (an orphan's parent).
- `BlockByHash` (10) - the reply to `GetBlockByHash`.

## Run

Fill in `.env` (see `../.env.sample`), then:

```
python main.py
```
