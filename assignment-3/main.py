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

from lab3_community import RegistrationCommunity

TIMEOUT = 30


async def run_client(group_id: str, blockchain_community_id: bytes, key_file: str) -> None:
    builder = ConfigBuilder().clear_keys().clear_overlays()
    builder.add_key("client", "curve25519", key_file)
    builder.add_overlay(
        "RegistrationCommunity",
        "client",
        [WalkerDefinition(Strategy.RandomWalk, 10, {"timeout": 3.0})],
        default_bootstrap_defs,
        {},
        [("started",)],
    )
    ipv8 = IPv8(
        builder.finalize(),
        extra_communities={"RegistrationCommunity": RegistrationCommunity},
    )
    overlay = ipv8.get_overlay(RegistrationCommunity)
    print(f"Public key: {overlay.my_peer.public_key.key_to_bin().hex()}")
    print(f"Blockchain community ID: {blockchain_community_id.hex()}")
    print("Joining registration community and waiting for the server...")
    overlay.configure(group_id, blockchain_community_id)
    await ipv8.start()

    try:
        result = await asyncio.wait_for(overlay.done_future, timeout=TIMEOUT)
        print(f"Done: success={result.success}, message={result.message!r}")
    except asyncio.TimeoutError:
        print(f"Timed out after {TIMEOUT}s — server not reached or no response.")
    finally:
        await ipv8.stop()


def require_env(key: str) -> str:
    value = os.environ.get(key)
    if value is None:
        raise Exception(f"{key} must be set.")
    return value


def main() -> None:
    load_dotenv()
    group_id = require_env("GROUP_ID")
    blockchain_community_id = bytes.fromhex(require_env("BLOCKCHAIN_COMMUNITY_ID"))
    key_file = require_env("KEY_FILE")

    asyncio.run(run_client(group_id, blockchain_community_id, key_file))


if __name__ == "__main__":
    main()
