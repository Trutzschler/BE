import asyncio
from dataclasses import dataclass

from ipv8.messaging.payload_dataclass import DataClassPayload, VariablePayload, vp_compile
from ipv8.community import Community, CommunitySettings
from ipv8.lazy_community import Peer, lazy_wrapper

#from common import SERVER_PUBLIC_KEY
SERVER_PUBLIC_KEY = bytes.fromhex("4c69624e61434c504b3a86b23934a28d669c390e2d1fc0b0870706c4591cc0cb178bc5a811da6d87d27ef319b2638ef60cc8d119724f4c53a1ebfad919c3ac4136c501ce5c09364e0ebb")

COMMUNITY_ID = bytes.fromhex("2c1cc6e35ff484f99ebdfb6108477783c0102881")

ROUNDS = 3

# We use @vp_compile rather than @dataclass, see assignment 1.
@vp_compile
class RegisterRequest(VariablePayload):
    msg_id = 1
    format_list = ["varlenH", "varlenH", "varlenH"]
    names = ["member1_key", "member2_key", "member3_key"]

@vp_compile
class RegisterResponse(VariablePayload):
    msg_id = 2
    format_list = ["?", "varlenHutf8", "varlenHutf8"]
    names = ["success", "group_id", "message"]

@vp_compile
class ChallengeRequest(VariablePayload):
    msg_id = 3
    format_list = ["varlenHutf8"]
    names = ["group_id"]

@vp_compile
class ChallengeResponse(VariablePayload):
    msg_id = 4
    format_list = ["varlenH", "q", "d"]
    names = ["nonce", "round_number", "deadline"]

@vp_compile
class BundleSubmission(VariablePayload):
    msg_id = 5
    format_list = ["varlenHutf8", "q", "varlenH", "varlenH", "varlenH"]
    names = ["group_id", "round_number", "sig1", "sig2", "sig3"]

@vp_compile
class RoundResult(VariablePayload):
    msg_id = 6
    format_list = ["?", "q", "q", "varlenHutf8"]
    names = ["success", "round_number", "rounds_completed", "message"]

@vp_compile
class ReadyNotification(VariablePayload):
    msg_id = 10
    format_list = []
    names = []

@vp_compile
class SignatureNotification(VariablePayload):
    msg_id = 11
    format_list = ["varlenH"]
    names = ["signature"]

@dataclass
class PeerInfo:
    peer: Peer
    ready: bool = False
    signature: bytes | None = None # signature for the round the original peer requested

class Lab2Community(Community):
    community_id = COMMUNITY_ID

    def __init__(self, settings: CommunitySettings) -> None:
        super().__init__(settings)
        self.add_message_handler(RegisterResponse, self.on_register_response)
        self.group_id: str | None = None
        self.server_key: str | None = None
        self.server: Peer | None = None
        self.teammates: dict[bytes, PeerInfo | None] = {}
        self.team_keys: list[bytes] | None = None
        self.own_index: int | None = None
        self.done_future: asyncio.Future | None = None
        self.request_round: int | None = None # the round for which this peer requested the challenge
        self.request_nonce: bytes | None = None # nonce for challenge requested by this peer

    def configure(self, server_key: str, group_id: str | None, teammates: list[bytes]) -> None:
        self.server_key = server_key
        for key in teammates:
            self.teammates[key] = None
        self.group_id = group_id

    def started(self) -> None:
        self.team_keys = sorted(self.teammates.keys() + [self.my_peer.key])
        self.own_index = self.team_keys.index(self.my_peer.key)

        if self.own_index == 0:
            if self.group_id == None:
                self.ez_send

    def try_start_phase_0(self) -> None:
        # only member 0 creates the group
        if self.own_index != 0:
            return

        if self.group_id != None:
            self.try_start_phase_1()
            return

        # At this point, we know that we're member 0 and do not have a group id yet,
        # so we'll try to create a group.
        if self.server == None:
            return

        self.create_group()

    def create_group(self) -> None:
        self.ez_send(self.server, RegisterRequest(**self.team_keys))

    def try_start_phase_1(self):
        if self.own_index != 0:
            return

        self.request_challenge()

    def request_challenge(self) -> None:
        self.ez_send(self.server, ChallengeRequest(self.group_id))

    def try_submit(self) -> None:
        # check if we have all signatures
        for mate in self.teammates.values():
            if mate.signature == None:
                return

        signatures = []
        for key in self.team_keys:
            if key == self.my_peer.key:
                signature = b"" # TODO
            else:
                signature = self.teammates[key].signature
            signatures.append(signature)

        round_number = -1 # TODO
        self.ez_send(self.server, BundleSubmission(self.group_id, round_number, **signatures))

    def on_peer_added(self, peer: Peer) -> None:
        print(f"Peer added: {peer}")
        if peer.mid.hex() in self.teammates:
            self.teammates[peer.mid.hex()] = PeerInfo(peer)

        if peer.key.hex() == self.server_key:
            self.server = peer

    def on_peer_removed(self, peer: Peer) -> None:
        print(f"Peer removed: {peer}")
        if peer.mid.hex() in self.teammates:
            self.teammates[peer.mid.hex()] = None

        if peer.key.hex() == self.server_key:
            self.server = None

    @lazy_wrapper(RegisterResponse)
    def on_register_response(self, peer: Peer, response: RegisterResponse) -> None:
        if self.own_index == 0:
            valid_sender = peer == self.server
        else:
            valid_sender = peer in map(lambda p: p.peer, self.teammates.values())

        if not valid_sender:
            print(f"Ignoring register response from invalid sender {peer}.")
            return

        print(f"Register response: {response}")
        if response.success:
            self.group_id = response.group_id

        if self.own_index == 0:
            for peer in self.teammates.values():
                self.ez_send(peer.peer, response)
        elif response.success:
            self.ez_send(peer, ReadyNotification())

    @lazy_wrapper(ReadyNotification)
    def on_ready_notification(self, peer: Peer, notification: ReadyNotification) -> None:
        if self.own_index != 0 or peer.key.key_to_bin() not in self.teammates.keys():
            print(f"Ignoring invalid ready notification from {peer}")
            return

        self.teammates[peer.key.key_to_bin()].ready = True
        self.try_start_phase_1()

    @lazy_wrapper(ChallengeResponse)
    def on_challenge_response(self, peer: Peer, response: ChallengeResponse) -> None:
        if peer != self.server or peer.key.key_to_bin() not in self.teammates.keys():
            print(f"Ignoring invalid challenge response from {peer}")
            return

        if response.round_number == self.request_round:
            for peer in self.teammates.values():
                self.ez_send(peer.peer, response)

        submitter_index = (response.round_number + 1) % len(self.team_keys)
        if self.own_index != submitter_index:
            submitter_peer = self.teammates[self.team_keys[submitter_index]].peer
            signature = b"" # TODO
            self.ez_send(submitter_peer, SignatureNotification(signature))

        self.try_submit()

    @lazy_wrapper(RoundResult)
    def on_round_result(self, peer: Peer, result: RoundResult) -> None:
        if peer != self.server:
            print(f"Ignoring invalid round result from {peer}")
            return

        print(f"Round result: {result}")

        if not result.success:
            print("Aborting")
            # TODO
            return

        if result.rounds_completed < ROUNDS:
            self.request_challenge()

