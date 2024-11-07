from typing import Any

from secp256k1proto.util import tagged_hash


BIP_TAG = "BIP DKG/"


def tagged_hash_bip_dkg(tag: str, msg: bytes) -> bytes:
    return tagged_hash(BIP_TAG + tag, msg)


def prf(seed: bytes, tag: str, extra_input: bytes = b"") -> bytes:
    return tagged_hash_bip_dkg(tag, seed + extra_input)


class SecretKeyError(ValueError):
    pass


class ThresholdError(ValueError):
    pass


class ProtocolError(Exception):
    pass


class FaultyParticipantOrCoordinatorError(ProtocolError):
    """Raised when another participant appears faulty.

    This is raised when another participant appears to have sent an invalid
    protocol message. This error does not necessarily imply that the suspected
    participant is faulty. It is always possible that the coordinator is faulty
    instead and has misrepresented the suspected particant's protocol messages.
    It is also possible that protocol message was simply not transmitted
    correctly.

    Attributes:
        participant (int): Index of the suspected participant.
    """

    def __init__(self, participant: int, *args: Any):
        self.participant = participant
        super().__init__(participant, *args)


class FaultyCoordinatorError(ProtocolError):
    """Raised when the coordinator appears faulty.

    This is raised when the coordinator appears to have sent an invalid protocol
    message. This error does not necessarily imply that the coordinator is
    faulty. It is also possible that a protocol message from the coordinator was
    simply not transmitted correctly.
    """


class UnknownFaultyPartyError(ProtocolError):
    """TODO"""

    def __init__(self, blame_state: Any, *args: Any):
        self.blame_state = blame_state
        super().__init__(*args)
