import asyncio
from dataclasses import dataclass

from ipv8.messaging.payload_dataclass import VariablePayload, vp_compile
from ipv8.community import Community, CommunitySettings
from ipv8.lazy_community import Peer, lazy_wrapper
from ipv8.peerdiscovery.network import PeerObserver

SERVER_PUBLIC_KEY = bytes.fromhex("4c69624e61434c504b3a82e33614a342774e084af80835838d6dbdb64a537d3ddb6c1d82011a7f101553cda40cf5fa0e0fc23abd0a9c4f81322282c5b34566f6b8401f5f683031e60c96")

COMMUNITY_ID = bytes.fromhex("4c61623247726f75705369676e696e6732303236")

ROUNDS = 3

# Timeout after which to resend a message if not implicit ACK was received.
RESEND_TIMEOUT = 3

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
class ReadyRequest(VariablePayload):
    msg_id = 10
    format_list = ["varlenHutf8"]
    names = ["group_id"]

@vp_compile
class ReadyResponse(VariablePayload):
    msg_id = 11
    format_list = []
    names = []

@vp_compile
class ChallengeNotification(VariablePayload):
    msg_id = 12
    format_list = ["varlenH", "q", "d", "varlenH"]
    names = ["nonce", "round_number", "deadline", "signature"]

@vp_compile
class ChallengeNotificationAck(VariablePayload):
    msg_id = 15
    format_list = ["q"]
    names = ["round_number"]

@vp_compile
class SignatureNotification(VariablePayload):
    msg_id = 13
    format_list = ["q", "varlenH"]
    names = ["round_number", "signature"]

@vp_compile
class DoneNotification(VariablePayload):
    msg_id = 14
    format_list = ["?", "varlenHutf8"]
    names = ["success", "message"]

@dataclass
class PeerInfo:
    peer: Peer
    ready: bool = False
    sent_challenge_ack: bool = False
    sent_group_id: bool = False # whether original peer has sent group id to this peer
    signature: bytes | None = None # signature for the round the original peer requested
    waiting_for: type | None = None # message type of response for which original peer is waiting

class Lab2Community(Community, PeerObserver):
    community_id = COMMUNITY_ID

    def __init__(self, settings: CommunitySettings) -> None:
        super().__init__(settings)
        self.add_message_handler(RegisterResponse, self.on_register_response)
        self.add_message_handler(RoundResult, self.on_round_result)
        self.add_message_handler(ReadyRequest, self.on_ready_request)
        self.add_message_handler(ReadyResponse, self.on_ready_response)
        self.add_message_handler(ChallengeResponse, self.on_challenge_response)
        self.add_message_handler(ChallengeNotification, self.on_challenge_notification)
        self.add_message_handler(ChallengeNotificationAck, self.on_challenge_notification_ack)
        self.add_message_handler(SignatureNotification, self.on_signature_notification)
        self.add_message_handler(DoneNotification, self.on_done_notification)
        self.group_id: str | None = None
        self.server: Peer | None = None
        self.teammates: dict[bytes, PeerInfo | None] = {}
        self.team_keys: list[bytes] | None = None
        self.own_index: int | None = None
        self.done_future: asyncio.Future | None = None
        self.submission_nonce: bytes | None = None # nonce for challenge submitted by this peer
        self.submission_round: int | None = None # the round for which this peer submits the challenge
        self.cached_challenge: ChallengeResponse | None = None
        self.received_ready_request: bool = False
        self.sent_ready_response: bool = False

    def configure(self, group_id: str | None, teammates: list[bytes]) -> None:
        for key in teammates:
            self.teammates[key] = None
        self.group_id = group_id
        self.done_future = asyncio.get_running_loop().create_future()

        self.team_keys = sorted(list(self.teammates.keys()) + [self.my_peer.public_key.key_to_bin()])
        self.own_index = self.team_keys.index(self.my_peer.public_key.key_to_bin())
        self.submission_round = self.get_submission_round_number()
        self.network.add_peer_observer(self)

        print(f"Own index: {self.own_index}")


    def started(self) -> None:
        self.run_part_1()

    def run_part_1(self) -> None:
        """
        Starts part 1 (group registration). If a group id is already provided, we will use that.
        Otherwise, we request a group id from the server.
        """
        if self.own_index == 0:
            print("Running part 1")
            self.obtain_group_id()

    def obtain_group_id(self) -> None:
        if self.group_id:
            self.distribute_group_id()
        elif self.server:
            self.create_group()
        else:
            print("No server found yet")

    def distribute_group_id(self) -> None:
        print(f"Distributing group id {self.group_id}")
        for mate in self.teammates.values():
            if mate and not mate.sent_group_id:
                mate.sent_group_id = True
                self.ez_send(mate.peer, ReadyRequest(self.group_id))

    def create_group(self) -> None:
        print(f"Creating group with keys {self.team_keys}")
        self.ez_send(self.server, RegisterRequest(*self.team_keys))

    def try_part_2(self):
        """
        Try to start part 2 (challenge rounds) if the whole team is ready. This method should only
        be called by team member 0.
        """
        if not self.is_team_ready():
            return

        self.request_challenge()

    def is_team_ready(self) -> bool:
        """
        Returns whether all teamates are ready for part 2.
        """
        return all(map(lambda p: p and p.ready, self.teammates.values()))

    def stop(self, success: bool, message: str) -> None:
        """
        Sends a done notification to all teammates.
        """
        for mate in self.teammates.values():
            if mate and mate.peer:
                self.ez_send(mate.peer, DoneNotification(success, message))

    def abort(self, message: str) -> None:
        """
        Send an done notification to all teammates indicating failure.
        """
        print(f"Aborting: {message}")
        self.stop(False, message)

    def finish(self, message: str) -> None:
        """
        Send an done notification to all teammates indicating success.
        """
        print(f"Finishing: {message}")
        self.stop(True, message)

    def request_challenge(self) -> None:
        """
        Request a challenge from the server.
        """
        self.ez_send(self.server, ChallengeRequest(self.group_id))

    def try_submit(self) -> None:
        """
        Try to submit the group signature to the server, if all teammates have sent their signature.
        """
        if not self.all_signatures_ready():
            return
        signatures = self.generate_group_signature()
        submission = BundleSubmission(self.group_id, self.submission_round, *signatures)
        print(f"Submitting {submission}")
        self.ez_send(self.server, submission)

    def all_signatures_ready(self):
        """
        Returns whether all teammates have sent their signatures for the round for which the current
        peer is responsible.
        """
        return all(map(lambda m: m.signature != None, self.teammates.values()))

    def generate_group_signature(self) -> list[bytes]:
        """
        Generates a group signature, assuming that all teammates have already sent their signatures.
        """
        signatures = []
        for key in self.team_keys:
            if key == self.my_peer.public_key.key_to_bin():
                signature = self.sign(self.submission_nonce)
            else:
                signature = self.teammates[key].signature
            signatures.append(signature)
        return signatures

    def register_signature(self, peer: Peer, signature: bytes) -> None:
        """
        Associate the given signature with the given peer for the round for which the current peer
        is responsible.
        """
        assert peer.public_key.key_to_bin() in self.teammates, "expected peer to be a teammate"
        self.teammates[peer.public_key.key_to_bin()].signature = signature

    def on_peer_added(self, peer: Peer) -> None:
        print(f"Peer added: {peer}")
        if peer.public_key.key_to_bin() in self.teammates:
            print("Peer is teammate")
            self.teammates[peer.public_key.key_to_bin()] = PeerInfo(peer)
            if self.group_id and self.own_index == 0:
                self.distribute_group_id()

            if self.own_index != 0:
                self.try_send_ready_response()

        if peer.public_key.key_to_bin() == SERVER_PUBLIC_KEY:
            print("Peer is server")
            self.server = peer
            self.run_part_1()

    def on_peer_removed(self, peer: Peer) -> None:
        print(f"Peer removed: {peer}")
        if peer.public_key.key_to_bin() in self.teammates:
            self.teammates[peer.public_key.key_to_bin()] = None

        if peer.public_key.key_to_bin() == SERVER_PUBLIC_KEY:
            self.server = None

    def is_server(self, peer):
        return self.server and peer == self.server

    def is_teammate(self, peer):
        return peer.public_key.key_to_bin() in self.teammates.keys()

    def is_teammate_with_id(self, peer, id):
        try:
            return self.team_keys.index(peer.public_key.key_to_bin()) == id
        except ValueError:
            return False

    def get_submission_round_number(self) -> int:
        """
        Returns the round number for which the current peer is responsible for submitting.
        """
        # convert from zero-based indexing to one-based indexing
        return 1 + (self.own_index - 1) % len(self.team_keys)

    def get_round_requester_index(self, round_number: int) -> int:
        """
        Gets the index (in the sorted list of team keys) of the peer responsible for requesting the
        challenge for the given round number.
        """
        return (round_number - 1) % len(self.team_keys)

    def get_round_submitter_index(self, round_number: int) -> int:
        """
        Gets the index (in the sorted list of team keys) of the peer responsible for submitting the
        challenge for the given round number.
        """
        return round_number % len(self.team_keys)

    def get_peer_by_index(self, index: int) -> Peer:
        """
        Retrieve a peer by its index in the sorted list of team keys.
        """
        if index == self.own_index:
            return self.my_peer
        else:
            key = self.team_keys[index]
            return self.teammates[key].peer

    def get_round_requester_peer(self, round_number) -> Peer:
        """
        Returns the peer responsible for requesting the challenge from the server for a given round
        number.
        """
        index = self.get_round_requester_index(round_number)
        return self.get_peer_by_index(index)

    def get_round_submitter_peer(self, round_number) -> Peer:
        """
        Returns the peer responsible for submitting the signatures to the server for a given round
        number.
        """
        index = self.get_round_submitter_index(round_number)
        return self.get_peer_by_index(index)

    def distribute_challenge(self, challenge: ChallengeResponse) -> None:
        """
        Sends the challenge to all teammates. The challenge is cached to handle implicit NACKs.
        """
        self.cached_challenge = challenge
        submitter = self.teammates[self.get_round_submitter_peer(challenge.round_number).public_key.key_to_bin()]
        f = lambda: self.distribute_challenge_impl(challenge)
        asyncio.ensure_future(self.do_until(f, submitter, ChallengeNotificationAck))

    def distribute_challenge_impl(self, challenge: ChallengeResponse) -> None:
        for mate in self.teammates.values():
            self.send_challenge_to(challenge, mate.peer)

    def send_challenge_to(self, challenge: ChallengeResponse, peer: Peer) -> None:
        """
        Forwards the challenge to the provided peer. If the provided peer is also the submitter,
        we include a signature to reduce the communication overhead.
        """
        if peer == self.get_round_submitter_peer(challenge.round_number):
            signature = self.sign(challenge.nonce)
        else:
            signature = b""

        self.ez_send(peer, ChallengeNotification(challenge.nonce, challenge.round_number, challenge.deadline, signature))

    def sign(self, nonce: bytes) -> bytes:
        return self.my_peer.key.signature(nonce)

    def resend_challenge_to(self, peer: Peer) -> None:
        """
        Resends the cached challenge to the provided peer.
        """
        if self.cached_challenge:
            self.send_challenge_to(self.cached_challenge, peer)

    def send_signature(self, submitter: PeerInfo, round_number: int, signature: bytes):
        f = lambda: self.ez_send(submitter.peer, SignatureNotification(round_number, signature))

        if round_number == ROUNDS:
            expected_message = DoneNotification
        else:
            expected_message = ChallengeNotification
        asyncio.ensure_future(self.do_until(f, submitter, expected_message))

    async def do_until(self, f, peer: PeerInfo, message_type: type, skip_first: bool = False) -> None:
        assert peer.waiting_for == None, f"teammate is already waiting for another response: {peer} (key: {peer.peer.public_key.key_to_bin().hex()}), trying to register {message_type}"
        peer.waiting_for = message_type

        if not skip_first:
            f()

        while peer.waiting_for:
            await asyncio.sleep(RESEND_TIMEOUT)
            f()

    def try_ack(self, peer: Peer, message_type: type) -> None:
        """
        Try to interpret received message as an implicit ACK.
        """
        mate = self.teammates[peer.public_key.key_to_bin()]
        if mate.waiting_for == message_type:
            mate.waiting_for = None

    def setup_challenge_retry(self, notification: ChallengeNotification) -> None:
        requester = self.get_round_requester_peer(notification.round_number)
        for peer in self.teammates.values():
            if peer.peer != requester and peer.signature == None:
                # this peer is not the requester and it has not sent a signature yet, so we resend
                # the challenge until it has sent a signature
                f = lambda: self.retry_challenge(peer.peer, notification)
                asyncio.ensure_future(self.do_until(f, peer, SignatureNotification, skip_first=True))

    def retry_challenge(self, peer: Peer, notification: ChallengeNotification) -> None:
        self.ez_send(peer, notification)

    def all_peers_discovered(self) -> bool:
        return all(map(lambda p: p, self.teammates.values()))

    def try_send_ready_response(self) -> None:
        if self.received_ready_request and not self.sent_ready_response and self.all_peers_discovered():
            peer_0 = self.teammates[self.team_keys[0]].peer
            self.sent_ready_response = True
            self.ez_send(peer_0, ReadyResponse())

    @lazy_wrapper(RegisterResponse)
    def on_register_response(self, peer: Peer, response: RegisterResponse) -> None:
        if self.own_index != 0 or not self.is_server(peer):
            print(f"Ignoring register response from invalid sender {peer}.")
            return

        print(f"Register response: {response}")
        if not response.success:
            self.abort("Could not register group.")
            return

        self.group_id = response.group_id
        self.distribute_group_id()

    @lazy_wrapper(ReadyRequest)
    def on_ready_request(self, peer: Peer, request: ReadyRequest) -> None:
        if self.own_index == 0 or not self.is_teammate_with_id(peer, 0):
            print(f"Ignoring ready request from invalid sender {peer}.")
            return

        print(f"Received ready request from {peer}: {request}")

        self.group_id = request.group_id
        self.received_ready_request = True
        self.try_send_ready_response()

    @lazy_wrapper(ReadyResponse)
    def on_ready_response(self, peer: Peer, response: ReadyResponse) -> None:
        if self.own_index != 0 or not self.is_teammate(peer):
            print(f"Ignoring invalid ready response from {peer}")
            return

        print(f"Received ready response from {peer}: {response}")

        if self.teammates[peer.public_key.key_to_bin()].ready:
            # we've already received a ready, so we interpret this as an implicit NACK
            self.resend_challenge_to(peer)
        else:
            self.teammates[peer.public_key.key_to_bin()].ready = True
            self.try_part_2()

    @lazy_wrapper(ChallengeResponse)
    def on_challenge_response(self, peer: Peer, response: ChallengeResponse) -> None:
        if not self.is_server(peer):
            print(f"Ignoring invalid challenge response from {peer}")
            return

        print(f"Received challenge response from {peer}: {response}")

        self.distribute_challenge(response)

    @lazy_wrapper(ChallengeNotification)
    def on_challenge_notification(self, peer: Peer, notification: ChallengeNotification):
        if peer not in [self.get_round_requester_peer(notification.round_number), self.get_round_submitter_peer(notification.round_number)]:
            print(f"Ignoring invalid challenge notification from {peer}")
            return

        print(f"Received challenge notification from {peer}: {notification}")

        self.try_ack(peer, ChallengeNotification)

        if self.get_round_submitter_index(notification.round_number) == self.own_index:
            self.ez_send(peer, ChallengeNotificationAck(notification.round_number))
            if self.submission_nonce == None:
                self.submission_nonce = notification.nonce
                # if we are the submitter for this round, we collect all signatures and try to submit
                if len(notification.signature) > 0:
                    self.register_signature(peer, notification.signature)
                self.setup_challenge_retry(notification)
                self.try_submit()
        else:
            # if we are not the submitter for this round, sign the nonce and send the signature to
            # the submitter
            signature = self.sign(notification.nonce)
            submitter_peer = self.get_round_submitter_peer(notification.round_number)
            submitter = self.teammates[submitter_peer.public_key.key_to_bin()]
            self.send_signature(submitter, notification.round_number, signature)

    @lazy_wrapper(ChallengeNotificationAck)
    def on_challenge_notification_ack(self, peer: Peer, ack: ChallengeNotificationAck):
        if not self.is_teammate(peer):
            print(f"Ignoring invalid challenge notification ack from {peer}")
            return

        print(f"Received challenge notification ack from {peer}: {ack}")

        self.teammates[peer.public_key.key_to_bin()].sent_challenge_ack = True
        self.try_ack(peer, ChallengeNotificationAck)

    @lazy_wrapper(SignatureNotification)
    def on_signature_notification(self, peer: Peer, notification: SignatureNotification):
        if not self.is_teammate(peer):
            print(f"Ignoring invalid signature notification from {peer}")
            return

        print(f"Received signature notification from {peer}: {notification}")
        self.try_ack(peer, SignatureNotification)

        if self.get_round_submitter_index(notification.round_number) == self.own_index:
            self.register_signature(peer, notification.signature)
            self.try_submit()
        else:
            print(f"I am not a submitter for round number {notification.round_number}")

    @lazy_wrapper(RoundResult)
    def on_round_result(self, peer: Peer, result: RoundResult) -> None:
        if not self.is_server(peer):
            print(f"Ignoring invalid round result from {peer}")
            return

        print(f"Received round result from {peer}: {result}")

        print(f"Round result: {result}")
        if not result.success:
            self.abort(f"Unsuccessful round: {result}")
            return

        if result.rounds_completed == ROUNDS:
            self.finish(f"All rounds completed successfully. Last round result: {result}")
        else:
            self.request_challenge()

    @lazy_wrapper(DoneNotification)
    def on_done_notification(self, peer: Peer, notification: DoneNotification) -> None:
        if not self.is_teammate(peer):
            print(f"Ignoring invalid done notification from {peer}")
            return

        self.try_ack(peer, DoneNotification)

        print(f"Done notification: {notification}")
        self.done_future.set_result(notification)

