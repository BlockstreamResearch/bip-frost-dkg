#!/usr/bin/env python3

"""Example of a full ChillDKG session"""

import argparse
import asyncio
import pprint
import sys
from random import randint
from secrets import token_bytes as random_bytes

from chilldkg_ref import chilldkg
from chilldkg_ref.chilldkg import (
    FaultyParticipantOrCoordinatorError,
    InvalidRecoveryAckError,
    RecoveryData,
    SessionParams,
    ThresholdInfo,
    UnknownFaultyParticipantOrCoordinatorError,
    coordinator_finalize,
    coordinator_investigate,
    coordinator_step1,
    hostpubkey_gen,
    params_hash,
    participant_finalize,
    participant_investigate,
    participant_recovery_ack_sign,
    participant_recovery_acks_verify,
    participant_step1,
    participant_step2,
)

#
# Network mocks to simulate full DKG sessions
#


class CoordinatorChannels:
    def __init__(self, n):
        self.n = n
        self.queues = []
        for i in range(n):
            self.queues += [asyncio.Queue()]

    def set_participant_queues(self, participant_queues):
        self.participant_queues = participant_queues

    def send_to(self, i, m):
        assert self.participant_queues is not None
        self.participant_queues[i].put_nowait(m)

    def send_all(self, m):
        assert self.participant_queues is not None
        for i in range(self.n):
            self.participant_queues[i].put_nowait(m)

    async def receive_from(self, i):
        item = await self.queues[i].get()
        return item


class ParticipantChannel:
    def __init__(self, coord_queue):
        self.queue = asyncio.Queue()
        self.coord_queue = coord_queue

    # Send m to coordinator
    def send(self, m):
        self.coord_queue.put_nowait(m)

    async def receive(self):
        item = await self.queue.get()
        return item


def connect(n):
    coord_chans = CoordinatorChannels(n)
    participant_chans = [ParticipantChannel(coord_chans.queues[i]) for i in range(n)]
    coord_chans.set_participant_queues([participant_chans[i].queue for i in range(n)])
    return coord_chans, participant_chans


#
# Helper functions
#


def pphex(thing):
    """Pretty print an object with bytes as hex strings"""

    def hexlify(thing):
        if isinstance(thing, bytes):
            return thing.hex()
        if isinstance(thing, dict):
            return {k: hexlify(v) for k, v in thing.items()}
        if hasattr(thing, "_asdict"):  # NamedTuple
            return hexlify(thing._asdict())
        if isinstance(thing, list):
            return [hexlify(v) for v in thing]
        return thing

    pprint.pp(hexlify(thing))


#
# Protocol parties
#


async def participant(
    chan: ParticipantChannel,
    hostseckey: bytes,
    params: SessionParams,
    investigation_procedure: bool,
) -> tuple[bytes, ThresholdInfo, RecoveryData]:
    # TODO Top-level error handling
    random = random_bytes(32)
    state1, pmsg1 = participant_step1(hostseckey, params, random)

    chan.send(pmsg1)
    cmsg1 = await chan.receive()

    # Participants can implement an optional investigation procedure. This
    # allows the participant to determine which participant is faulty when an
    # `UnknownFaultyParticipantOrCoordinatorError` is raised. The investigation
    # procedure requires the participant to receive an extra "investigation
    # message" from the coordinator that contains necessary information.
    #
    # In this example, if the investigation procedure is enabled, the
    # participant expects the coordinator to send a investigation message.
    # Alternatively, an implementation of the participant can explicitly request
    # the investigation message only if participant_step2 fails.
    if investigation_procedure:
        cinv = await chan.receive()

    try:
        aux_rand = random_bytes(32)
        state2, pmsg2 = participant_step2(hostseckey, state1, cmsg1, aux_rand)
    except UnknownFaultyParticipantOrCoordinatorError as e:
        if investigation_procedure:
            participant_investigate(e, cinv)
        else:
            # If this participant does not implement the investigation
            # procedure, it cannot determine which party is faulty. Re-raise
            # UnknownFaultyParticipantOrCoordinatorError in this case.
            raise

    chan.send(pmsg2)
    cmsg2 = await chan.receive()

    return participant_finalize(state2, cmsg2)


async def coordinator(
    chans: CoordinatorChannels, params: SessionParams, investigation_procedure: bool
) -> tuple[ThresholdInfo, RecoveryData]:
    (hostpubkeys, _) = params
    n = len(hostpubkeys)

    pmsgs1 = []
    for i in range(n):
        pmsgs1.append(await chans.receive_from(i))
    state, cmsg1 = coordinator_step1(pmsgs1, params)
    chans.send_all(cmsg1)

    # If the coordinator implements the investigation procedure and it is
    # enabled, it sends an extra message to the participants.
    if investigation_procedure:
        cinv_msgs = coordinator_investigate(pmsgs1, params)
        for i in range(n):
            chans.send_to(i, cinv_msgs[i])

    pmsgs2 = []
    for i in range(n):
        pmsgs2.append(await chans.receive_from(i))
    cmsg2, threshold_info, recovery_data = coordinator_finalize(state, pmsgs2)
    chans.send_all(cmsg2)

    return threshold_info, recovery_data


#
# DKG Session
#


# This is a dummy participant used to demonstrate the investigation procedure.
# It picks a random victim participant and sends an invalid share to it.
async def faulty_participant(
    chan: ParticipantChannel,
    hostseckey: bytes,
    params: SessionParams,
    participant_id: int,
):
    n = len(params.hostpubkeys)
    random = random_bytes(32)
    _, pmsg1 = participant_step1(hostseckey, params, random)
    pmsg1_parsed = chilldkg.ParticipantMsg1.from_bytes(pmsg1, t=params.t, n=n)

    assert len(pmsg1_parsed.enc_pmsg.enc_shares) == n
    # Pick random victim that is not this participant
    victim = (participant_id + randint(1, n - 1)) % n
    pmsg1_parsed.enc_pmsg.enc_shares[victim] += 17

    chan.send(pmsg1_parsed.to_bytes())


def simulate_chilldkg_full(
    hostseckeys: list[bytes], params: SessionParams, faulty_id: int | None
) -> list[tuple[bytes | None, ThresholdInfo, RecoveryData] | None]:
    n = len(hostseckeys)
    assert n == len(params.hostpubkeys)

    # For demonstration purposes, we enable the investigation procedure if a
    # participant is faulty.
    investigation_procedure = faulty_id is not None

    async def session():
        coord_chans, participant_chans = connect(n)
        coroutines = [coordinator(coord_chans, params, investigation_procedure)] + [
            participant(
                participant_chans[i], hostseckeys[i], params, investigation_procedure
            )
            if i != faulty_id
            else faulty_participant(participant_chans[i], hostseckeys[i], params, i)
            for i in range(n)
        ]
        return await asyncio.gather(*coroutines)

    (cthreshold_info, crecovery_data), *poutputs = asyncio.run(session())
    # The coordinator has no secret share.
    return [(None, cthreshold_info, crecovery_data), *poutputs]


#
# Acknowledgment round (optional)
#
# A successful DKG session does not imply that the other participants deem the
# session successful and hold a copy of the recovery data. Before the threshold
# public key is used (e.g., before funds are sent to it), the party that is
# going to use it should therefore obtain acknowledgments from all
# participants. This is an application-level step after the DKG session, and
# it can also happen later, e.g., when the first address is generated.


async def participant_ack(
    chan: ParticipantChannel,
    hostseckey: bytes,
    params: SessionParams,
    recovery_data: RecoveryData,
):
    # The participant acknowledges its own copy of the recovery data. It should
    # send the acknowledgment only after it has stored the recovery data
    # durably.
    aux_rand = random_bytes(32)
    ack = participant_recovery_ack_sign(hostseckey, recovery_data, params, aux_rand)
    chan.send(ack)


async def coordinator_collect_acks(
    chans: CoordinatorChannels, params: SessionParams, recovery_data: RecoveryData
):
    # The acknowledgments should be verified by the party that is going to use
    # the threshold public key. In this example, this is the coordinator, e.g.,
    # because it derives addresses. If a participant uses the key, it should
    # obtain the acknowledgments (e.g., relayed by the coordinator) and verify
    # them itself rather than rely on the coordinator's verification, because
    # the coordinator is untrusted.
    n = len(params.hostpubkeys)
    ack_sigs = []
    for i in range(n):
        ack_sigs.append(await chans.receive_from(i))
    # Raises InvalidRecoveryAckError if an acknowledgment is invalid.
    participant_recovery_acks_verify(recovery_data, params, ack_sigs)


def simulate_acknowledgments(
    hostseckeys: list[bytes],
    params: SessionParams,
    recovery_data: RecoveryData,
    precovery_data: list[RecoveryData],
):
    n = len(hostseckeys)

    async def session():
        coord_chans, participant_chans = connect(n)
        coroutines = [coordinator_collect_acks(coord_chans, params, recovery_data)] + [
            participant_ack(
                participant_chans[i], hostseckeys[i], params, precovery_data[i]
            )
            for i in range(n)
        ]
        await asyncio.gather(*coroutines)

    asyncio.run(session())


def main():
    parser = argparse.ArgumentParser(description="ChillDKG example")
    parser.add_argument(
        "--faulty-participant",
        action="store_true",
        help="When this flag is set, one random participant will send an invalid message, and the investigation procedure will be enabled for other participants and the coordinator.",
    )
    parser.add_argument(
        "t", nargs="?", type=int, default=2, help="Signing threshold [default = 2]"
    )
    parser.add_argument(
        "n", nargs="?", type=int, default=3, help="Number of participants [default = 3]"
    )
    args = parser.parse_args()
    t = args.t
    n = args.n
    if args.faulty_participant:
        faulty_id = randint(0, n - 1)
    else:
        faulty_id = None

    print("====== ChillDKG example session ======")
    print(f"Using n = {n} participants and a threshold of t = {t}.")
    if faulty_id is not None:
        print(f"Participant {faulty_id} is faulty.")
    print()

    # Generate common inputs for all participants and coordinator
    hostseckeys = [random_bytes(32) for _ in range(n)]
    hostpubkeys = []
    for i in range(n):
        hostpubkeys += [hostpubkey_gen(hostseckeys[i])]
    params = SessionParams(hostpubkeys, t)

    print("=== Host secret keys ===")
    pphex(hostseckeys)
    print()

    print("=== Session parameters ===")
    pphex(params)
    print()
    print(f"Session parameters hash: {params_hash(params).hex()}")
    print()

    try:
        rets = simulate_chilldkg_full(hostseckeys, params, faulty_id)
    except FaultyParticipantOrCoordinatorError as e:
        print(
            f"A participant has failed and is blaming either participant {e.participant_id} or the coordinator."
        )
        # If the blamed participant is the faulty participant, exit with code 0.
        # Otherwise, re-raise the exception.
        if faulty_id == e.participant_id:
            return 0
        else:
            raise

    assert len(rets) == n + 1
    print("=== Coordinator's threshold info ===")
    _, threshold_info, _ = rets[0]
    pphex({"threshold_info": threshold_info})
    print()

    for i in range(n):
        print(f"=== Participant {i}'s secret share and threshold info ===")
        secshare, threshold_info, _ = rets[i + 1]
        pphex({"secshare": secshare, "threshold_info": threshold_info})
        print()

    # Check that all RecoveryData of all parties is identical
    assert len({ret[-1] for ret in rets}) == 1
    recovery_data = rets[0][2]
    print(f"=== Common recovery data ({len(recovery_data)} bytes) ===")
    print(recovery_data.hex())
    print()

    print("=== Acknowledgments ===")
    try:
        simulate_acknowledgments(
            hostseckeys, params, recovery_data, [ret[2] for ret in rets[1:]]
        )
    except InvalidRecoveryAckError as e:
        # The DKG session itself was successful. We only cannot confirm that
        # this participant holds a copy of the recovery data. Keep all outputs
        # and host secret keys, but do not use the threshold public key yet.
        print(
            f"Participant {e.participant_id} has not acknowledged the recovery data. "
            "Do not use the threshold public key yet."
        )
    else:
        print("All participants have acknowledged the recovery data.")
        print("The threshold public key can now be used.")


if __name__ == "__main__":
    sys.exit(main())
