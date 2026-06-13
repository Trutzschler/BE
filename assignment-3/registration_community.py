from ipv8.messaging.payload_dataclass import VariablePayload, vp_compile
from ipv8.community import Community, CommunitySettings
from ipv8.lazy_community import Peer, lazy_wrapper
from ipv8.peerdiscovery.network import PeerObserver

REGISTRATION_SERVER_PUBLIC_KEY: bytes = bytes.fromhex(
    "4c69624e61434c504b3ae3fc099fb56ca3b5e1de9a1c843387f2acdbb78b1bd4350ffde518068a0d246344b10d0d8c355fd0d76873e7d7f7838f3715e025af08f791324495e083331ce6"
)

REGISTRATION_COMMUNITY_ID: bytes = bytes.fromhex(
    "4c616233426c6f636b636861696e323032365057"
)


@vp_compile
class RegisterBlockchain(VariablePayload):
    msg_id = 1
    format_list = ["varlenHutf8", "varlenH"]
    names = ["group_id", "community_id"]


@vp_compile
class RegisterResponse(VariablePayload):
    msg_id = 2
    format_list = ["?", "varlenHutf8"]
    names = ["success", "message"]


class RegistrationCommunity(Community, PeerObserver):
    """
    Connects to the Lab 3 registration server and registers the blockchain community ID.
    """

    community_id = REGISTRATION_COMMUNITY_ID

    def __init__(self, settings: CommunitySettings) -> None:
        super().__init__(settings)
        self.add_message_handler(RegisterResponse, self.on_register_response)
        self.server: Peer | None = None
        self.group_id: str | None = None
        self.blockchain_community_id: bytes | None = None

    def configure(self, group_id: str, blockchain_community_id: bytes) -> None:
        self.group_id = group_id
        self.blockchain_community_id = blockchain_community_id
        self.network.add_peer_observer(self)

    def started(self) -> None:
        pass

    def send_register(self) -> None:
        print(
            f"Registering blockchain with group_id={self.group_id!r}, "
            f"community_id={self.blockchain_community_id.hex()}"
        )
        self.ez_send(
            self.server, RegisterBlockchain(self.group_id, self.blockchain_community_id)
        )

    def on_peer_added(self, peer: Peer) -> None:
        if peer.public_key.key_to_bin() == REGISTRATION_SERVER_PUBLIC_KEY:
            print("Registration server discovered.")
            self.server = peer

    def on_peer_removed(self, peer: Peer) -> None:
        if peer.public_key.key_to_bin() == REGISTRATION_SERVER_PUBLIC_KEY:
            self.server = None

    @lazy_wrapper(RegisterResponse)
    def on_register_response(self, peer: Peer, response: RegisterResponse) -> None:
        if peer.public_key.key_to_bin() != REGISTRATION_SERVER_PUBLIC_KEY:
            print(
                f"Ignoring RegisterResponse from non-server peer {peer.public_key.key_to_bin().hex()}"
            )
            return

        print(
            f"RegisterResponse: success={response.success}, message={response.message!r}"
        )
