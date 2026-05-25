# CS4150 Blockchain Engineering

# Lab 1: Proof of Work over IPv8

## Overview

In this assignment, you will build an IPv8 client **from scratch** that:

1. Connects to a running server via the IPv8 peer-to-peer network
2. Computes a Proof of Work (PoW) over your email **and** your GitHub repo URL
3. Submits the solution as an IPv8 message
4. Receives a response from the server (accepted or rejected)

Your public key is registered on the server upon success. **You are responsible for preserving your private key** (`.pem` file) — it is your identity for the rest of the course. If you do lose it before the deadline, the server allows re-registration with a fresh key against your existing email (see below), so you won't be locked out. Avoid this if you can. **After the deadline, the server is taken offline — no further submissions or re-registrations are possible.**

## Server Information

| Parameter | Value |
|-----------|-------|
| Community ID | `2c1cc6e35ff484f99ebdfb6108477783c0102881` (20 bytes / 40 hex) |
| Server Public Key | `4c69624e61434c504b3a86b23934a28d669c390e2d1fc0b0870706c4591cc0cb178bc5a811da6d87d27ef319b2638ef60cc8d119724f4c53a1ebfad919c3ac4136c501ce5c09364e0ebb` (74 bytes / 148 hex) |
| Difficulty | 28 leading zero bits |
| Deadline | `2026-05-12T23:59:59 UTC` — after this time the server is shut down and no further submissions are possible |

You reach the server through IPv8's standard peer-discovery mechanism (see the [py-ipv8 documentation](https://py-ipv8.readthedocs.io/)). Join the community using the `community_id` above, and IPv8 will find peers in the community; your client then picks out the server from among them by matching the public key above.

**Verify the server before trusting responses.** Other peers in the community (e.g., your classmates' clients) will also be discoverable. Your client must filter peers by the server's public key; do not send your submission to, or accept responses from, peers whose public key doesn't match.

## Requirements

- Python 3.10+
- py-ipv8 library: https://github.com/Tribler/py-ipv8
- Read the py-ipv8 documentation: https://py-ipv8.readthedocs.io/
- A **public GitHub repository** containing the source code of your client. The URL of this repo is part of your submission, and changing it later requires re-solving the PoW. Course staff may review this repository during grading; make sure it contains the full source of the client you used to submit.

## Proof of Work

### The Challenge

Find a nonce (non-negative integer) such that:

```
SHA256( email_utf8 || "\n" || github_url_utf8 || "\n" || nonce_as_8_byte_big_endian )
```

has at least **28 leading zero bits** (i.e., the first 3 bytes are all zeros *and* the next byte is < 16).

`||` means byte concatenation. `"\n"` is the single ASCII newline byte (`0x0A`) used as a field separator. Neither your email nor your URL may contain a newline.

### Hash Computation

The hash input is, in order:

1. Your official TU Delft student email address, encoded as UTF-8 bytes. Must end in `@tudelft.nl` or `@student.tudelft.nl` and be ≤ 254 bytes. The address is canonicalised for identity purposes (NFC, whitespace stripped, lowercased), but the PoW hash is verified against the exact bytes you submit — whatever you hash locally is what the server will hash.
2. A single `\n` byte.
3. The URL of your public GitHub repo for this lab, encoded as UTF-8 bytes. Must be non-empty, ≤ 512 bytes, and contain no whitespace or control characters. The server does **not** verify that the URL resolves or that the repository is reachable — that is your responsibility.
4. A single `\n` byte.
5. Your nonce, encoded as a **64-bit big-endian integer** (8 bytes). The wire format on the payload is a signed int64 (struct code `q`), but valid nonces are non-negative; i.e., `0 ≤ nonce ≤ 2^63 − 1`. Negative values will be rejected by the server.

With 28-bit difficulty, you should expect to try approximately 2^28 (~268 million) nonces before finding a valid one — typically 2–3 minutes on a laptop with an optimised loop, 5–8 minutes with a naive one. PoW search is a geometric process with high variance: on an unlucky run you may need 10–20 minutes even on fast hardware, so design your system to survive a long search (don't time out your own mining loop, persist progress if you can). **Any optimisations are very welcome.**

### Wire Protocol

Once you find a valid nonce, send it to the server as an IPv8 message.

#### Submission Message (message_id = 1)

| Field        | Logical Type | IPv8 Wire Format | Description |
|--------------|--------------|------------------|-------------|
| `email`      | UTF-8 string | `varlenHutf8`    | Your TU Delft email address |
| `github_url` | UTF-8 string | `varlenHutf8`    | URL of your public GitHub repo |
| `nonce`      | integer      | `q`              | The nonce that solves the PoW |

#### Server Response (message_id = 2)

| Field     | Logical Type | IPv8 Wire Format | Description |
|-----------|--------------|------------------|-------------|
| `success` | boolean      | `?`              | `True` if your submission is accepted |
| `message` | UTF-8 string | `varlenHutf8`    | Human-readable result |

Both messages are authenticated using IPv8's `BinMemberAuthenticationPayload`. Your public key is automatically included and verified by IPv8 authentication; it is not part of the message payload.

#### Server Responses

| Response | Meaning |
|----------|---------|
| `success=True, message="Accepted"` | Your PoW is valid, you are registered |
| `success=True, message="Accepted (already registered)"` | Same (email, key, URL) resubmission — you already passed |
| `success=True, message="Accepted (github URL updated)"` | Same key and email, new URL with a fresh valid PoW |
| `success=True, message="Accepted (re-registered with new key)"` | Same email, new key — e.g., a lost-key recovery |
| `success=False, message="Rejected: invalid hash — need 28 leading zero bits, got N"` | Your hash doesn't meet the difficulty |
| `success=False, message="Rejected: this public key is already registered with a different email"` | You can only use one email per key |
| `success=False, message="Rejected: email must be a well-formed TU Delft address ..."` | Email is empty, malformed, or the domain is not `tudelft.nl` / `student.tudelft.nl` |
| `success=False, message="Rejected: github_url must be non-empty, ≤ 512 chars, and contain no whitespace/control chars"` | GitHub URL field failed validation |
| `success=False, message="Rejected: nonce must be a non-negative integer that fits in 63 bits"` | Nonce is negative or ≥ 2^63 |
| `success=False, message="Rejected: malformed submission payload ..."` | Packet reached the server but fields couldn't be decoded as `(email: string, github_url: string, nonce: int64)` |

### Policy on Identity Changes

- **One email per public key.** Once you register with an email, that email is permanently bound to your key. Submitting the same key with a different email is rejected.
- **Changing the GitHub URL (before the deadline).** Submit the same (email, key) with the new URL and a fresh valid PoW over that URL; the server will reply `Accepted (github URL updated)`.
- **Lost-key re-registration (before the deadline).** If you lose your `.pem`, you may submit a fresh key with the same email and a valid PoW; the server will reply `Accepted (re-registered with new key)`.
- **After the deadline.** The server is stopped at `2026-05-12T23:59:59 UTC`. Submissions, URL edits, and re-registrations are all impossible once that happens.

## Grading

- **Pass/fail.** The server either has your public key registered as passed by the deadline, or it doesn't.
- **Deadline: `2026-05-12T23:59:59 UTC`.** After this time the server is stopped; no further submissions are possible.

## Tips

- Start by reading the py-ipv8 overlay tutorials. Understand how communities, messages, and peer discovery work before writing code.
- Test your PoW computation locally before trying to send anything over the network.
- Decide your GitHub URL **before** mining. Mining a nonce binds you to that specific URL string; changing even a trailing `/` will invalidate the hash and require mining again.
- Use `curve25519` as your key generation type (IPv8 default).
- Your client must register a handler for the response message (`message_id = 2`) so it can receive the server's reply.
- The server verifies the sender's identity via IPv8's built-in message authentication. You do not need to include your public key in the message payload.
- If you get "invalid hash" responses, double-check your hash construction matches the spec exactly: UTF-8 encoding for both strings, `\n` separators, 8-byte big-endian nonce, SHA-256.
- If you get no response at all (timeout), the most likely cause is that your packet isn't being properly signed by IPv8 — unsigned or wrongly-signed packets are dropped without a reply. Make sure your client uses IPv8's standard authenticated send (e.g. `ez_send`) so the submission carries a valid signature for your key.

### Minimum Client Checklist

Your client must be able to:

1. Load or generate an IPv8 key pair
2. Join the Lab 1 community using the community ID above
3. Discover the server peer through IPv8 peer discovery
4. Compute a valid PoW over `(email, github_url, nonce)`
5. Send the submission message with your email, github URL, and nonce
6. Receive and display the server response

### Common Failure Cases

- Encoding the nonce in the wrong byte order
- Hashing the text form of the nonce instead of its 8-byte binary form
- Forgetting the `\n` separators in the hash input
- Accidentally including a trailing newline or whitespace in your URL string
- Using a non-TU-Delft email domain
- Changing your URL without re-mining a nonce for the new URL
- Forgetting to register a handler for the response message
- Accepting any peer in the community as the server instead of filtering by the server's public key
- Accidentally using a different private key than the one you intend to keep for later labs

## Deliverable

A working IPv8 client that:

1. Connects to the server's community
2. Computes and submits a valid PoW with your email and github URL
3. Receives and displays the server's response

You are done when you receive `Accepted`, `Accepted (already registered)`, `Accepted (github URL updated)`, or `Accepted (re-registered with new key)`.

There is nothing to submit manually. The repository URL you submitted is the canonical location of your client code; your public key is your proof of completion.

# Lab 2: Coordinated Group Signing over IPv8

## Overview

You and two teammates build IPv8 clients that sign challenges from a server within a strict shared budget.

Each round, the server issues a 32-byte nonce. All 3 members sign it; one collects the 3 signatures and submits the bundle. Across 3 rounds, each must be submitted by a different member. **All 3 rounds must finish inside 10 seconds wall-clock**, measured from the moment the server sends the round-1 nonce. Faster groups earn bonus credit — the lab is graded on speed, not just correctness.

## Server

| Parameter | Value |
|---|---|
| Community ID | `4c61623247726f75705369676e696e6732303236` (20 bytes / 40 hex) |
| Server public key | `4c69624e61434c504b3a82e33614a342774e084af80835838d6dbdb64a537d3ddb6c1d82011a7f101553cda40cf5fa0e0fc23abd0a9c4f81322282c5b34566f6b8401f5f683031e60c96` (74 bytes / 148 hex) |
| Group size | 3 |
| Rounds | 3 (different submitter each round) |
| Total budget | **10 seconds wall-clock for all 3 rounds combined**, starting when the server sends the round-1 nonce |
| Deadline | `2026-05-19T23:59:59 UTC` |

Reach the server via IPv8 peer discovery on the community ID above. Filter peers by the published public key — never trust a peer whose key does not match.

## Prerequisites and deliverable

- Use the **same Ed25519 key pair** each member used in Lab 1. The server checks every member's key against Lab 1's records and rejects any key not found there.
- Add your Lab 2 client code to the **same personal GitHub repository** each member registered in Lab 1. Each member commits to their own repo.
- If a teammate lost their Lab 1 key, they recover it in Lab 1 first (`email + new key`), then your trio registers a fresh Lab 2 group with the new key. Old groups stay on the records and are harmless.

## Wire-level authentication

Send every message — to the server and to teammates — with IPv8's authenticated send (`ez_send` and friends). Each packet carries a `BinMemberAuthenticationPayload` with your public key and a signature over the payload. The server reads your key from this header to identify you.

Unsigned packets are dropped silently. If you get no reply at all, check this first.

## Part 1: Group registration

### Register (message_id = 1)

Any member sends:

| Field | Type | Wire | Description |
|---|---|---|---|
| `member1_key` | bytes | `varlenH` | Ed25519 public key of member 1 |
| `member2_key` | bytes | `varlenH` | Ed25519 public key of member 2 |
| `member3_key` | bytes | `varlenH` | Ed25519 public key of member 3 |

The order you list the keys here is the **canonical signature order** for every later bundle.

### Response (message_id = 2)

| Field | Type | Wire |
|---|---|---|
| `success` | bool | `?` |
| `group_id` | str | `varlenHutf8` |
| `message` | str | `varlenHutf8` |

| Response | Meaning |
|---|---|
| `success=True, "Group registered"` | New group, fresh `group_id` returned |
| `success=True, "Group already registered"` | A group with this exact 3-member set already exists; the same `group_id` is returned (UDP-retry safe) |
| `success=False, "Rejected: sender must be a group member"` | Sender's key is not one of the 3 listed keys |
| `success=False, "Rejected: duplicate public keys"` | Two or 3 of the listed keys are equal |
| `success=False, "Rejected: public keys not in Lab 1 records: <hex>[, <hex>]"` | One or more keys never passed Lab 1; the server lists the offending keys verbatim |

A pubkey may belong to multiple groups (recovery path). The server does not block re-registration if a member is already in another group.

## Part 2: Challenge rounds

Your group must complete **3 rounds, each submitted by a different member**. The server identifies the submitter by the IPv8 peer key on the bundle's auth header.

### Challenge request (message_id = 3)

| Field | Type | Wire |
|---|---|---|
| `group_id` | str | `varlenHutf8` |

### Challenge response (message_id = 4)

The server replies with a nonce. **The 10-second wall-clock timer starts when the round-1 response is sent** and runs until the round-3 bundle is accepted. The same deadline applies to all 3 rounds.

| Field | Type | Wire | Description |
|---|---|---|---|
| `nonce` | bytes | `varlenH` | 32 random bytes |
| `round_number` | int | `q` | 1, 2, or 3 |
| `deadline` | float | `d` | Unix timestamp — the same value for every challenge in this group |

Re-requesting during a live round returns the same nonce, round, and deadline; it does not extend the budget.

### Bundle submission (message_id = 5)

| Field | Type | Wire |
|---|---|---|
| `group_id` | str | `varlenHutf8` |
| `round_number` | int | `q` |
| `sig1` | bytes | `varlenH` |
| `sig2` | bytes | `varlenH` |
| `sig3` | bytes | `varlenH` |

Each `sigN` is an Ed25519 signature over the **raw 32-byte nonce** by `memberN`'s private key. Order must match the registration order.

### Round result (message_id = 6)

| Field | Type | Wire |
|---|---|---|
| `success` | bool | `?` |
| `round_number` | int | `q` |
| `rounds_completed` | int | `q` |
| `message` | str | `varlenHutf8` |

A `RoundResultPayload` (message_id = 6) is the server's reply to **both** a `SignatureBundle` (success / verdict) **and** an early-rejection of a `ChallengeRequest` that the server cannot fulfil. Cases:

| Response | Triggered by | Meaning |
|---|---|---|
| `success=True, "Round N recorded at T.TTs of 10s (M/3)"` | Bundle | Accepted. `T.TT` is wall-clock seconds since the round-1 challenge — your running total against the 10-second budget. |
| `success=True, "Round 3 recorded at T.TTs of 10s — all 3 rounds done"` | Bundle | All rounds in. `T.TT` is your **combined elapsed** — the bonus signal. Lower is better. |
| `success=False, "Rejected: budget exceeded (T.TTs elapsed)"` | Bundle | The 10-second window closed before the bundle arrived. The group must re-register to retry. |
| `success=False, "Rejected: invalid signature from member N"` | Bundle | Signature N did not verify against member N's registered key. The active challenge stays live; fix and resubmit before the budget closes. |
| `success=False, "Rejected: submitter already used in a previous round"` | Bundle | A different teammate must submit. |
| `success=False, "Rejected: wrong round number"` | Bundle | `round_number` does not match the current active round. |
| `success=False, "Rejected: submitter is not a member of this group"` | Bundle | Submitter's IPv8 key is not one of the 3 registered keys. |
| `success=False, "Rejected: no active challenge for this group"` | Bundle | No live challenge: the budget already closed, or this bundle duplicates a successful submission. |
| `success=False, "Rejected: group not found"` | Challenge request | `group_id` does not match any registered group. |
| `success=False, "Rejected: requester is not a member of this group"` | Challenge request | The peer asking for a challenge is not one of the 3 registered members. (Parallel wording to the bundle-path "submitter is not a member..." rejection.) |
| `success=False, "Rejected: group already completed all rounds"` | Challenge request | The group is already at `rounds_completed=3`. No more challenges will be issued. |

## Coordination

The server sees `ChallengeRequest` going in and `SignatureBundle` coming out. Everything between is your design.

Your teammates appear as peers in the same Lab 2 community. Filter by their public keys to recognise them; route group-internal messages within it.

For example:

- **Coordinator.** One member relays the nonce, collects signatures, submits.
- **Broadcast.** Everyone sends to everyone; whoever has all 3 signatures first submits.
- **Round-robin.** Pre-assign a different submitter per round; each runs their own round.

## Grading

The server records every accepted round and its timing. Grading happens after the deadline, using that data.

- **Baseline.** 3 accepted rounds, 3 different submitters, all inside the 10-second window, on or before `2026-05-19T23:59:59 UTC`. Each member earns credit individually.
- **System Design.** The 10-second window leaves room for choices: how many messages, who relays what, what happens on packet loss. 
- **Bonus** Faster, simpler, more robust designs score higher than ones that scrape by.

## Common pitfalls

- Sending a registration request from a peer that is not one of the 3 listed members.
- Using a key that did not pass Lab 1 (the server names the offending key in hex).
- Reordering signatures relative to registration order.
- Reusing the same submitter across rounds.
- Burning the 10-second window before round 3 lands.
- Hammering challenge requests during a live round expecting a fresh budget — the server returns the same challenge until the budget closes.
- Forgetting to register handlers for response messages.
- Accepting any peer in the community as the server instead of filtering by public key.

# Lab 3: PoW Blockchain over IPv8

## Overview

You and your two teammates from Lab 2 build IPv8 nodes that together run a 3-node Proof-of-Work blockchain. Each member runs one node. Your nodes must mine blocks, propagate them, converge on a single chain, and answer queries from the Lab 3 server.

Once you register, the Lab 3 server joins your blockchain community, submits a test transaction, and walks every chain to check PoW, header linking, body commitment, and 3-way consistency. Your group passes the first time those checks all hold.

## Server

| Parameter | Value |
|---|---|
| Registration Community ID | `4c616233426c6f636b636861696e323032365057` (= ASCII `Lab3Blockchain2026PW`, 20 bytes / 40 hex) |
| Server public key | `4c69624e61434c504b3ae3fc099fb56ca3b5e1de9a1c843387f2acdbb78b1bd4350ffde518068a0d246344b10d0d8c355fd0d76873e7d7f7838f3715e025af08f791324495e083331ce6` (74 bytes / 148 hex) |
| Group size | 3 (same composition as Lab 2) |
| Required confirmations | 3 |
| Per-attempt timeout | 5 minutes |
| Deadline | `2026-06-12T23:59:59 UTC` |

Reach the server through IPv8 peer discovery on the registration community ID above. Filter peers by the published public key — never trust a peer whose key does not match.

## Prerequisites and deliverable

- Use the **same IPv8 key pair** each member used in Labs 1 and 2 — whatever key type you registered with (`curve25519`, `medium`, `high`, …). Signature verification on test transactions goes through `ECCrypto.key_from_public_bin()`, so any IPv8 key type works.
- Add your Lab 3 client code to the **same personal GitHub repository** each member registered in Lab 1.
- The deliverable is a working blockchain node. There is nothing to submit manually — the server records your group's pass, and you receive an email at the address from Lab 1 when it lands.

## Wire-level authentication

Send every message — to the server and to teammates — with IPv8's authenticated send (`ez_send` and friends). Each packet carries a `BinMemberAuthenticationPayload` with your public key and a signature over the payload. The server reads your key from this header to identify you. Unsigned packets are dropped silently.

## Part 1: Register your blockchain

Before grading, register your blockchain's community ID with the Lab 3 server on the **Registration Community**.

### Register Blockchain (message_id = 1)

Sent by any group member.

| Field | Type | Wire | Description |
|---|---|---|---|
| `group_id` | str | `varlenHutf8` | Your group ID from Lab 2 |
| `community_id` | bytes | `varlenH` | 20-byte community ID of your blockchain |

### Register Response (message_id = 2)

| Field | Type | Wire | Description |
|---|---|---|---|
| `success` | bool | `?` | True if registered |
| `message` | str | `varlenHutf8` | Human-readable result |

Once your registration is recorded, the server joins your blockchain community and runs a check within a few minutes. If your 3 nodes aren't fully online yet when the first attempt fires, the server retries automatically — **up to 3 retries per registration**. After that, automatic retries stop until you register again.

**Re-registering is allowed at any time** and resets the retry counter. Send `RegisterBlockchain` again to trigger a fresh batch of attempts. Re-registering with a different `community_id` replaces the recorded community for your group; subsequent attempts run against the new chain.

## Part 2: Respond to server queries

Inside **your** blockchain community (the one identified by the `community_id` you registered), your nodes implement handlers for the queries the server sends them.

### Submit Transaction (message_id = 1)

| Field | Type | Wire | Description |
|---|---|---|---|
| `sender_key` | bytes | `varlenH` | IPv8 public key of the signer |
| `data` | bytes | `varlenH` | Arbitrary payload bytes |
| `timestamp` | int | `q` | Unix timestamp |
| `signature` | bytes | `varlenH` | Signature over `sender_key + data + timestamp_8byte_be` |

Verify the signature, add the transaction to your mempool, and respond.

### Submit Transaction Response (message_id = 2)

| Field | Type | Wire | Description |
|---|---|---|---|
| `success` | bool | `?` | True if accepted into your mempool |
| `tx_hash` | bytes | `varlenH` | 32-byte transaction hash (formula in *Block format* below) |
| `message` | str | `varlenHutf8` | Human-readable result |

### Get Chain Height (message_id = 3)

| Field | Type | Wire | Description |
|---|---|---|---|
| `request_id` | int | `q` | Identifier for matching the response |

### Chain Height Response (message_id = 4)

| Field | Type | Wire | Description |
|---|---|---|---|
| `request_id` | int | `q` | Matching request identifier |
| `height` | int | `q` | Current chain height (genesis = 0) |
| `tip_hash` | bytes | `varlenH` | Hash of the latest block header |

### Get Block (message_id = 5)

| Field | Type | Wire | Description |
|---|---|---|---|
| `height` | int | `q` | Block height to fetch |

### Block Response (message_id = 6)

| Field | Type | Wire | Description |
|---|---|---|---|
| `height` | int | `q` | Block height |
| `prev_hash` | bytes | `varlenH` | Previous block hash (32 bytes) |
| `txs_hash` | bytes | `varlenH` | Commitment to the block's transactions (32 bytes) |
| `timestamp` | int | `q` | Block timestamp |
| `difficulty` | int | `q` | Declared difficulty in leading zero bits |
| `nonce` | int | `q` | PoW nonce |
| `block_hash` | bytes | `varlenH` | Hash of this block header (32 bytes) |
| `tx_hashes` | bytes | `varlenH` | Concatenated 32-byte transaction hashes, in block order. `b""` for an empty block. |

## Block format

### Header (84 bytes)

```
prev_hash    (32 bytes)
txs_hash     (32 bytes)
timestamp    ( 8 bytes, uint64 big-endian)
difficulty   ( 4 bytes, uint32 big-endian)
nonce        ( 8 bytes, uint64 big-endian)
```

`block_hash = SHA256(header_bytes)` over those 84 bytes, in that order. **PoW rule:** `block_hash` must have at least `difficulty` leading zero bits. Choose the value of `difficulty` for each block yourself; it's part of the header.

### Transaction hash

`tx_hash = SHA256(sender_key || data || timestamp_8byte_be || signature)`

### Body commitment

`txs_hash = SHA256(tx_hash_1 || tx_hash_2 || ... || tx_hash_n)` over the block's transactions in the order they appear. An empty block uses `txs_hash = SHA256(b"")`.

When the server fetches a block, it splits `tx_hashes` into 32-byte chunks, recomputes the SHA-256 over the concatenation, and confirms it matches the header's `txs_hash`.

## Consensus

Your 3 nodes must converge on a single chain. The longest chain rule is the canonical answer: when a block arrives, validate it (PoW satisfies its declared `difficulty`, `prev_hash` links cleanly, `txs_hash` matches the body), then append, fork-switch, or ignore depending on whether it extends, overtakes, or stays behind your current tip.

How you detect, fetch, and apply forks is your design call. The server only requires that all 3 nodes agree on the same chain.

## Grading

Pass/fail. The server records the outcome the first time your group's chain clears every check below. Once recorded, the pass is sticky — re-registering after passing doesn't undo it. Submissions after the deadline are flagged late.

Each check is over the chain returned by your 3 nodes during one attempt:

- **Transaction accepted.** The node receiving the server's Submit Transaction returns `success = True`.
- **Chain integrity.** Every block has a valid PoW for its declared `difficulty`, and `prev_hash` of each block matches its parent's `block_hash`.
- **Body commitment.** Recomputed `SHA256(tx_hash_1 || ... || tx_hash_n)` over the test transaction's block matches that block's `txs_hash`.
- **Confirmations.** The test transaction is buried under at least 3 blocks on every node.
- **Consistency.** All 3 nodes agree on the same `block_hash` at every confirmed height.

Each attempt requires all 3 of your nodes to be online and reachable for its duration (around 5 minutes). With automatic retries (up to 3 per registration) plus unlimited re-registration, you don't need to be online at any specific moment — just keep your nodes running until you receive the pass email.

## Tips

- Build the chain primitives first (block header packing, hashing, PoW search, the flat `txs_hash` commitment) and unit-test them before introducing peers.
- Get single-node mining and chain validation working before you wire up propagation.
- All 3 of your nodes must agree on the same chain at every height — including the very first block. Pick a within-group convention for what your block 0 looks like and make sure every node boots up with it.

## Common pitfalls

- Encoding `timestamp`, `difficulty`, or `nonce` in the wrong byte order or width.
- Hashing the text form of an integer instead of its big-endian binary form.
- Forgetting that `txs_hash` for an empty block is `SHA256(b"")`, not 32 zero bytes.
- Three nodes that mine independently but don't propagate cleanly, leaving each on its own private chain, i.e., the consistency check fails immediately.
- Registering before all 3 nodes are reachable; the first attempt fails with no inclusion. Just re-register once they're up.
- Accepting any peer in the community as the server instead of filtering by the published public key.

# How to run

## Assignment 1
Run
```bash
uv run assignment-1/main.py
```
to run the code for assignment 1.
The code mines a nonce (or uses a precomputed one) with a configurable
difficulty target (28 by default),
and uses this to send the submission message to the server.
Before running the code make sure to create a `.env` file containing the
following (see `.env.sample`):
- `EMAIL`: included in the submission message.
- `GITHUB_URL`: included in the submission message.
- `KEY_FILE`: path to store the private key (`.pem` file) for this client.
- `PRECOMPUTED_NONCE` (optional): precomputed nonce to avoid mining when re-running the code.

## Assignment 2
To run assignment 2, run

```bash
uv run assignment-2/main.py
```

The `.env` file should contain:
- `TEAMMATES`: public keys (hexadecimal) of teammates. Order does not matter, as they will be sorted anyway.
- `GROUP_ID`: group id (optional).
- `KEY_FILE`: path to store the private key (`.pem` file) for this client.
