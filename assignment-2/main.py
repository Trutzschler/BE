import asyncio
from dotenv import load_dotenv
from ipv8.configuration import (
    ConfigBuilder,
    Strategy,
    WalkerDefinition,
    default_bootstrap_defs,
)
from ipv8_service import IPv8
import os

from lab_2_community import Lab2Community

TIMEOUT = 15

async def run_client(email: str, github_url: str, key_file: str, nonce: bytes) -> None:
    builder = ConfigBuilder().clear_keys().clear_overlays()
    builder.add_key("client", "curve25519", key_file)
    builder.add_overlay(
        "Lab2Community",
        "client",
        [WalkerDefinition(Strategy.RandomWalk, 10, {"timeout": 3.0})],
        default_bootstrap_defs,
        {},
        [("started",)],
    )
    ipv8 = IPv8(
        builder.finalize(),
        extra_communities={"Lab2Community": Lab2Community},
    )
    await ipv8.start()
    overlay = ipv8.get_overlay(Lab2Community)
    print(f"Public key: {overlay.my_peer.public_key.key_to_bin().hex()}")
    print(f"Peer mid: {overlay.my_peer.mid.hex()}")
    # print(f"Server pubkey: {SERVER_PUBLIC_KEY.hex()}")
    print("Joining community and waiting for the server to be discovered...")
    overlay.configure(email, github_url, nonce)

    try:
        done = await asyncio.wait_for(
            overlay.done_future,
            timeout=TIMEOUT,
        )

        print(f"Done")

    except asyncio.TimeoutError:
        print(f"Still running after {TIMEOUT:.0f}s. ")
    finally:
        await ipv8.stop()


def require_env(key: str) -> str:
    value = os.environ.get(key)
    if value == None:
        raise Exception(f"{key} must be set.")
    return value

def main() -> None:
    load_dotenv()
    teammates = require_env("TEAMMATES")
    key_file = require_env("KEY_FILE")

    asyncio.run(run_client(email, github_url, key_file, nonce))

if __name__ == "__main__":
    main()

if __name__ == "__main__":
    main()