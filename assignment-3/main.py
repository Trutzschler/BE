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

from registration_community import RegistrationCommunity
from blockchain_community import BlockchainCommunity


TIMEOUT = 30


async def run_client(
    group_id: str,
    blockchain_community_id: bytes,
    key_file: str,
    teammates: list[bytes],
    force_register: bool,
) -> None:
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
    my_key = overlay.my_peer.public_key.key_to_bin()
    should_register = force_register or my_key == min({my_key, *teammates})
    print(f"Public key: {my_key.hex()}")
    print(f"Blockchain community ID: {blockchain_community_id.hex()}")
    print(f"Designated registrar: {should_register}")
    print("Joining registration community and waiting for the server...")
    overlay.configure(group_id, blockchain_community_id, should_register)
    await ipv8.start()

    try:
        result = await asyncio.wait_for(overlay.done_future, timeout=TIMEOUT)
        print(f"Done: success={result.success}, message={result.message!r}")
    except asyncio.TimeoutError:
        print(f"Timed out after {TIMEOUT}s: server not reached or no response.")
    finally:
        await ipv8.stop()


def require_env(key: str) -> str:
    value = os.environ.get(key)
    if not value:
        raise Exception(f"{key} must be set.")
    return value


def main() -> None:
    load_dotenv()
    group_id = require_env("GROUP_ID")
    blockchain_community_id = bytes.fromhex(require_env("BLOCKCHAIN_COMMUNITY_ID"))
    if len(blockchain_community_id) != 20:
        raise Exception(
            f"BLOCKCHAIN_COMMUNITY_ID must be 20 bytes / 40 hex, got {len(blockchain_community_id)} bytes."
        )
    BlockchainCommunity.community_id = blockchain_community_id
    key_file = require_env("KEY_FILE")

    teammates_env = os.environ.get("TEAMMATES", "")
    teammates = [
        bytes.fromhex(s.strip()) for s in teammates_env.split(",") if s.strip()
    ]
    force_register = bool(os.environ.get("FORCE_REGISTER"))

    asyncio.run(
        run_client(
            group_id, blockchain_community_id, key_file, teammates, force_register
        )
    )


if __name__ == "__main__":
    main()
