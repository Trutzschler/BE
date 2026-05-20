import asyncio
from ipv8.community import Community
from ipv8.configuration import ConfigBuilder, Strategy, WalkerDefinition, default_bootstrap_defs
from ipv8.lazy_community import lazy_wrapper
from ipv8.messaging.lazy_payload import VariablePayloadWID
from ipv8.peer import Peer
from ipv8_service import IPv8

class SubmissionMessage(VariablePayloadWID):
    msg_id = 1
    format_list = ["varlenHutf8", "varlenHutf8", "q"]
    names = ["email", "github_url", "nonce"]

class ResponseMessage(VariablePayloadWID):
    msg_id = 2
    format_list = ["?", "varlenHutf8"]
    names = ["success", "message"]

SERVER_PUBLIC_KEY = bytes.fromhex(
    "4c69624e61434c504b3a86b23934a28d669c390e2d1fc0b0870706c4591cc0cb178bc5a811da6d87d27ef319b2638ef60cc8d119724f4c53a1ebfad919c3ac4136c501ce5c09364e0ebb"
)

class Lab1Community(Community):
    community_id = bytes.fromhex("2c1cc6e35ff484f99ebdfb6108477783c0102881")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.add_message_handler(ResponseMessage, self.on_response)
        self.response_received = asyncio.Event()

        self.email = "m.a.trutzschlervonfalkenstein@student.tudelft.nl"
        self.github_url = "https://github.com/Trutzschler/BE"
        self.nonce = 45546580

    def get_server(self) -> Peer | None:
        for peer in self.get_peers():
            if peer.public_key.key_to_bin() == SERVER_PUBLIC_KEY:
                return peer
        return None

    async def wait_for_server_and_submit(self):
        print("Looking for server...")
        while True:
            server = self.get_server()
            if server:
                print("Found server! Sending submission...")
                self.ez_send(server, SubmissionMessage(
                    email=self.email,
                    github_url=self.github_url,
                    nonce=self.nonce
                ))
                return
            await asyncio.sleep(1)

    @lazy_wrapper(ResponseMessage)
    def on_response(self, peer: Peer, payload: ResponseMessage):
        print(f"\n── Server Response ──────────────────")
        print(f"Success : {payload.success}")
        print(f"Message : {payload.message}")
        print(f"────────────────────────────────────\n")
        self.response_received.set()

async def main():
    # Load your saved private key
    from ipv8.keyvault.crypto import default_eccrypto
    with open("my_key.pem", "rb") as f:
        key = default_eccrypto.key_from_private_bin(f.read())

    builder = ConfigBuilder().clear_keys().clear_overlays()
    builder.add_key("my key", "curve25519", "my_key.pem")
    builder.add_overlay(
        "Lab1Community",
        "my key",
        [WalkerDefinition(Strategy.RandomWalk, 10, {"timeout": 3.0})],
        default_bootstrap_defs,
        {},
        []
    )

    ipv8 = IPv8(builder.finalize(), extra_communities={"Lab1Community": Lab1Community})
    await ipv8.start()

    community = ipv8.get_overlay(Lab1Community)
    await community.wait_for_server_and_submit()

    # Wait until the response arrives (or timeout after 60s)
    try:
        await asyncio.wait_for(community.response_received.wait(), timeout=60)
    except asyncio.TimeoutError:
        print("Timed out waiting for server response.")
    await ipv8.stop()

asyncio.run(main())