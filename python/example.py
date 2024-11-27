#!/usr/bin/env python3

"""Example of a full ChillDKG session"""

from typing import Tuple, List, Optional
import asyncio
import pprint
from random import randint
from secrets import token_bytes as random_bytes
import sys
import argparse

from chilldkg_ref.chilldkg import (
    hostpubkey_gen,
    participant_step1,
    participant_step2,
    participant_finalize,
    participant_blame,
    coordinator_step1,
    coordinator_finalize,
    coordinator_blame,
    SessionParams,
    DKGOutput,
    RecoveryData,
    FaultyParticipantOrCoordinatorError,
    UnknownFaultyParticipantOrCoordinatorError,
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


#
# Protocol parties
#


async def participant(
    chan: ParticipantChannel, hostseckey: bytes, params: SessionParams, blame_mode: bool
) -> Tuple[DKGOutput, RecoveryData]:
    # TODO Top-level error handling
    random = random_bytes(32)
    state1, pmsg1 = participant_step1(hostseckey, params, random)

    chan.send(pmsg1)
    cmsg1 = await chan.receive()

    # Participants can implement an optional blame mode. This allows the
    # participant to determine which participant is faulty in case of a protocol
    # failure. Blaming requires the participant to receive an extra "blame
    # message" from the coordinator that contains necessary information.
    #
    # In this example, if blame mode is enabled, the participant expects the
    # coordinator to send a blame message. Alternatively, an implementation of
    # the participant can explicitly request the blame message only if
    # participant_step2 fails.
    if blame_mode:
        cblame = await chan.receive()

    try:
        state2, eq_round1 = participant_step2(hostseckey, state1, cmsg1)
    except UnknownFaultyParticipantOrCoordinatorError as e:
        if blame_mode:
            participant_blame(e.blame_state, cblame)
        else:
            # If this participant does not support blame mode, it cannot
            # determine which party is faulty. Re-raise UnknownFaultyPartyError
            # in this case.
            raise

    chan.send(eq_round1)
    cmsg2 = await chan.receive()

    return participant_finalize(state2, cmsg2)


async def coordinator(
    chans: CoordinatorChannels, params: SessionParams, blame_mode: bool
) -> Tuple[DKGOutput, RecoveryData]:
    (hostpubkeys, t) = params
    n = len(hostpubkeys)

    pmsgs1 = []
    for i in range(n):
        pmsgs1.append(await chans.receive_from(i))
    state, cmsg1 = coordinator_step1(pmsgs1, params)
    chans.send_all(cmsg1)

    # If the coordinator implements blame mode and it is enabled, it sends an
    # extra message to the participants.
    if blame_mode:
        blame_msgs = coordinator_blame(pmsgs1)
        for i in range(n):
            chans.send_to(i, blame_msgs[i])

    sigs = []
    for i in range(n):
        sigs += [await chans.receive_from(i)]
    cmsg2, dkg_output, recovery_data = coordinator_finalize(state, sigs)
    chans.send_all(cmsg2)

    return dkg_output, recovery_data


#
# DKG Session
#


# This is a dummy participant used to demonstrate blame mode. It picks a random
# victim participant and sends an invalid share to it.
async def faulty_participant(
    chan: ParticipantChannel, hostseckey: bytes, params: SessionParams, idx: int
):
    random = random_bytes(32)
    _, pmsg1 = participant_step1(hostseckey, params, random)

    n = len(pmsg1.enc_pmsg.enc_shares)
    # Pick random victim that is not this participant
    victim = (idx + randint(1, n - 1)) % n
    pmsg1.enc_pmsg.enc_shares[victim] += 17

    chan.send(pmsg1)


def simulate_chilldkg_full(
    hostseckeys, t, faulty_idx
) -> Optional[List[Tuple[DKGOutput, RecoveryData]]]:
    # Generate common inputs for all participants and coordinator
    n = len(hostseckeys)
    hostpubkeys = []
    for i in range(n):
        hostpubkeys += [hostpubkey_gen(hostseckeys[i])]

    # TODO also print params_id
    params = SessionParams(hostpubkeys, t)

    # For demonstration purposes, we enable blame mode if a participant is
    # faulty.
    blame_mode = faulty_idx is not None

    async def session():
        coord_chans = CoordinatorChannels(n)
        participant_chans = [
            ParticipantChannel(coord_chans.queues[i]) for i in range(n)
        ]
        coord_chans.set_participant_queues(
            [participant_chans[i].queue for i in range(n)]
        )
        coroutines = [coordinator(coord_chans, params, blame_mode)] + [
            participant(participant_chans[i], hostseckeys[i], params, blame_mode)
            if i != faulty_idx
            else faulty_participant(participant_chans[i], hostseckeys[i], params, i)
            for i in range(n)
        ]
        return await asyncio.gather(*coroutines)

    outputs = asyncio.run(session())
    return outputs


def main():
    n = 5
    t = 3
    hostseckeys = [random_bytes(32) for _ in range(n)]
    parser = argparse.ArgumentParser(description="ChillDKG example")

    parser.add_argument(
        "--faulty-participant",
        action="store_true",
        help="When this flag is set, one random participant will send an invalid message, and blame mode will be enabled for other participants and the coordinator.",
    )

    args = parser.parse_args()
    if args.faulty_participant:
        faulty_idx = randint(0, n - 1)
    else:
        faulty_idx = None

    # TODO Move more steps into the async methods. It's not an issue for the
    # tests to have prints in the async methods, we can suppress them, see
    # https://stackoverflow.com/a/28321717.
    print("=== Inputs ===")
    print(f"t: {t}")
    print(f"n: {n}")
    if faulty_idx is not None:
        print(f"Participant {faulty_idx} is faulty")
    for i in range(n):
        print(f"Participant {i}'s hostseckey:", hostseckeys[i].hex())
    print()

    try:
        rets = simulate_chilldkg_full(hostseckeys, t, faulty_idx)
    except FaultyParticipantOrCoordinatorError as e:
        print(
            f"A participant has failed and is blaming either participant {e.participant} or the coordinator."
        )
        # If the blamed participant is the faulty participant, exit with code 0.
        # Otherwise, re-raise the exception.
        if faulty_idx == e.participant:
            return 0
        else:
            raise

    assert len(rets) == n + 1
    print("=== Coordinator's DKGOutput ===")
    dkg_output, _ = rets[0]
    pprint.pp(dkg_output._asdict())
    print()

    for i in range(n):
        print(f"=== Participant {i}'s DKGOutput ===")
        dkg_output, _ = rets[i + 1]
        pprint.pp(dkg_output._asdict())
        print()

    # Check that all RecoveryData of all parties is identical
    assert len(set([rets[i][1] for i in range(n + 1)])) == 1
    recovery_data = rets[0][1]
    print(f"=== Common RecoveryData ({len(recovery_data)} bytes)===")
    print(recovery_data)


if __name__ == "__main__":
    sys.exit(main())
