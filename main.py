import asyncio
import os

from dotenv import load_dotenv
from ipv8.configuration import (
    ConfigBuilder,
    Strategy,
    WalkerDefinition,
    default_bootstrap_defs,
)
from ipv8_service import IPv8

from common import SERVER_PUBLIC_KEY
from lab_1_community import Lab1Community
from mine import compute_target, mine, nonce_byte_to_int, verify_nonce

DIFFICULTY = 28
TIMEOUT = 120

async def run_client(email: str, github_url: str, key_file: str, nonce: bytes) -> None:
    builder = ConfigBuilder().clear_keys().clear_overlays()
    builder.add_key("client", "curve25519", key_file)
    builder.add_overlay(
        "Lab1Community",
        "client",
        [WalkerDefinition(Strategy.RandomWalk, 10, {"timeout": 3.0})],
        default_bootstrap_defs,
        {},
        [],
    )
    ipv8 = IPv8(
        builder.finalize(),
        extra_communities={"Lab1Community": Lab1Community},
    )
    await ipv8.start()
    overlay = ipv8.get_overlay(Lab1Community)
    print(f"Public key: {overlay.my_peer.public_key.key_to_bin().hex()}")
    print(f"Peer mid: {overlay.my_peer.mid.hex()}")
    print(f"Server pubkey: {SERVER_PUBLIC_KEY.hex()}")
    print("Joining community and waiting for the server to be discovered...")
    overlay.configure(email, github_url, nonce)

    try:
        response = await asyncio.wait_for(
            overlay.response_future,
            timeout=TIMEOUT,
        )

        print(f"Done. Response: {response}")

    except asyncio.TimeoutError:
        print(f"No response after {TIMEOUT:.0f}s. ")
    finally:
        await ipv8.stop()

def mine_nonce(email: str, github_url: str, precomputed: str | None) -> bytes:
    prefix = f"{email}\n{github_url}\n".encode()
    if precomputed:
        nonce = bytes.fromhex(precomputed)
        target = compute_target(DIFFICULTY)
        assert verify_nonce(prefix, target, nonce), "PRECOMPUTED_NONCE was set but is invalid"
        print(f"Using precomputed nonce: {nonce.hex()}")
    else:
        print(f"No precomputed nonce found. Mining a nonce with difficulty {DIFFICULTY}. This may take a minute...")
        nonce = mine(prefix, DIFFICULTY)
        print(f"Found nonce: {nonce.hex()}")

    return nonce_byte_to_int(nonce)

def require_env(key: str) -> str:
    value = os.environ.get(key)
    if value == None:
        raise Exception(f"{key} must be set.")
    return value

def main() -> None:
    load_dotenv()
    email = require_env("EMAIL")
    github_url = require_env("GITHUB_URL")
    key_file = require_env("KEY_FILE")
    precomputed_nonce = os.environ.get("PRECOMPUTED_NONCE")

    nonce = mine_nonce(email, github_url, precomputed_nonce)
    asyncio.run(run_client(email, github_url, key_file, nonce))

if __name__ == "__main__":
    main()
