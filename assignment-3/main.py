import asyncio
import os
import time

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

# How often the supervisor re-sends RegisterBlockchain once the group is ready.
REGISTER_INTERVAL = 90.0
# How often the supervisor checks readiness.
SUPERVISOR_TICK = 5.0


def add_overlay(builder: ConfigBuilder, name: str) -> None:
    builder.add_overlay(
        name,
        "client",
        [WalkerDefinition(Strategy.RandomWalk, 10, {"timeout": 3.0})],
        default_bootstrap_defs,
        {},
        [],
    )


async def run_node(
    group_id: str,
    blockchain_community_id: bytes,
    key_file: str,
    teammates: list[bytes],
    force_register: bool,
    port: int = 8090,
) -> None:
    builder = ConfigBuilder().clear_keys().clear_overlays()
    builder.set_port(port)
    builder.add_key("client", "curve25519", key_file)
    add_overlay(builder, "RegistrationCommunity")
    add_overlay(builder, "BlockchainCommunity")
    ipv8 = IPv8(
        builder.finalize(),
        extra_communities={
            "RegistrationCommunity": RegistrationCommunity,
            "BlockchainCommunity": BlockchainCommunity,
        },
    )
    reg = ipv8.get_overlay(RegistrationCommunity)
    bc = ipv8.get_overlay(BlockchainCommunity)

    my_key = reg.my_peer.public_key.key_to_bin()
    should_register = force_register or my_key == min({my_key, *teammates})
    print(f"Public key: {my_key.hex()}")
    print(f"Blockchain community ID: {blockchain_community_id.hex()}")
    print(f"Designated registrar: {should_register}")

    bc.configure(set(teammates))
    reg.configure(group_id, blockchain_community_id, on_passed=bc.announce_passed)
    await ipv8.start()
    bc.start_mining()
    print("Mining started; running until interrupted.")

    last_register = 0.0
    try:
        while not bc.stop_event.is_set():
            now = time.monotonic()
            ready = should_register and reg.server is not None and bc.teammates_ready()
            if ready and now - last_register >= REGISTER_INTERVAL:
                reg.send_register()
                last_register = now
            bc.announce_tip()
            print(
                f"height={bc.height} tip={bc.tip_hash.hex()[:12]} "
                f"teammates={len(bc.connected_teammates())}/{len(bc.teammates)} "
                f"mempool={len(bc.pending_txs())}"
            )
            await asyncio.sleep(SUPERVISOR_TICK)
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
    port = int(os.environ.get("PORT", "8090"))

    try:
        asyncio.run(
            run_node(
                group_id, blockchain_community_id, key_file, teammates, force_register, port
            )
        )
    except KeyboardInterrupt:
        print("Shutting down.")


if __name__ == "__main__":
    main()
