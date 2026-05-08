import asyncio
from dataclasses import dataclass

from ipv8.messaging.payload_dataclass import DataClassPayload, VariablePayload, vp_compile
from ipv8.community import Community, CommunitySettings
from ipv8.lazy_community import Peer, lazy_wrapper

from common import SERVER_PUBLIC_KEY

COMMUNITY_ID = bytes.fromhex("2c1cc6e35ff484f99ebdfb6108477783c0102881")

@dataclass
class SubmissionPayload(DataClassPayload[1]):
    email: str
    github_url: str
    nonce: int


@dataclass
class ServerResponsePayload(DataClassPayload[2]):
    success: bool
    message: str

# We use @vp_compile rather than @dataclass, since the latter gives problems:
# if no defaults are set, then an exception is raised about the dataclass being constructed without
# arguments.
# If defaults are set, then IPv8 generates invalid code...
@vp_compile
class SubmissionPayload(VariablePayload):
    msg_id = 1
    format_list = ["varlenHutf8", "varlenHutf8", "q"]
    names = ["email", "github_url", "nonce"]


@vp_compile
class ServerResponsePayload(VariablePayload):
    msg_id = 2
    format_list = ["?", "varlenHutf8"]
    names = ["success", "message"]

class Lab1Community(Community):
    community_id = COMMUNITY_ID

    def __init__(self, settings: CommunitySettings) -> None:
        super().__init__(settings)
        self.add_message_handler(ServerResponsePayload, self.on_response)
        self.email: str = ""
        self.github_url: str = ""
        self.nonce: int = 0
        self.response_future: asyncio.Future | None = None
        self._submitted_to: set[bytes] = set()
        asyncio.ensure_future(self._run())

    def configure(self, email: str, github_url: str, nonce: int) -> None:
        self.email = email
        self.github_url = github_url
        self.nonce = nonce
        self.response_future = asyncio.get_running_loop().create_future()

    async def _run(self) -> None:
        print("Searching for server...")
        server = await self._find_server()
        print(f"Server found: {server}")
 
        submission = SubmissionPayload(self.email, self.github_url, self.nonce)
        print(f"Sending submission: {submission}")
        self.ez_send(server, submission)

    async def _find_server(self) -> Peer:
        while True:
            for peer in self.get_peers():
                if peer.public_key.key_to_bin() == SERVER_PUBLIC_KEY:
                    return peer
            print("Server not found among peers. Trying again in a few seconds.")
            await asyncio.sleep(3.0)

    def on_peer_added(self, peer: Peer) -> None:
        print(f"Peer added: {peer}")

    def on_peer_removed(self, peer: Peer) -> None:
        print(f"Peer removed: {peer}")

    @lazy_wrapper(ServerResponsePayload)
    def on_response(self, peer: Peer, payload: ServerResponsePayload) -> None:
        if peer.public_key.key_to_bin() != SERVER_PUBLIC_KEY:
            print(f"Ignoring response from {peer}, which is not the server.")
            return

        print(f"Response: {payload}")
        if self.response_future is not None and not self.response_future.done():
            self.response_future.set_result(payload)
