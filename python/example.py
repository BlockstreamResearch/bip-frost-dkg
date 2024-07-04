#!/usr/bin/env python3

"""Example of a full ChillDKG session"""

from typing import Tuple, List
import asyncio
import pprint
from secrets import token_bytes as random_bytes
import sys

from chilldkg_ref.chilldkg import (
    hostpubkey,
    session_params,
    participant_step1,
    participant_step2,
    participant_finalize,
    coordinator_step1,
    coordinator_finalize,
    SessionParams,
    DKGOutput,
    RecoveryData,
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
    chan: ParticipantChannel, seed: bytes, params: SessionParams
) -> Tuple[DKGOutput, RecoveryData]:
    # TODO Top-level error handling
    random = random_bytes(32)
    state1, pmsg1 = participant_step1(seed, params, random)
    chan.send(pmsg1)
    cmsg1 = await chan.receive()

    state2, eq_round1 = participant_step2(seed, state1, cmsg1)

    chan.send(eq_round1)
    cmsg2 = await chan.receive()

    return participant_finalize(state2, cmsg2)


async def coordinator(
    chans: CoordinatorChannels, params: SessionParams
) -> Tuple[DKGOutput, RecoveryData]:
    (hostpubkeys, t) = params
    n = len(hostpubkeys)

    pmsgs1 = []
    for i in range(n):
        pmsgs1.append(await chans.receive_from(i))
    state, cmsg1 = coordinator_step1(pmsgs1, params)
    chans.send_all(cmsg1)

    sigs = []
    for i in range(n):
        sigs += [await chans.receive_from(i)]
    cmsg2, dkg_output, recovery_data = coordinator_finalize(state, sigs)
    chans.send_all(cmsg2)

    return dkg_output, recovery_data


#
# DKG Session
#


def simulate_chilldkg_full(seeds, t) -> List[Tuple[DKGOutput, RecoveryData]]:
    # Generate common inputs for all participants and coordinator
    n = len(seeds)
    hostpubkeys = []
    for i in range(n):
        hostpubkeys += [hostpubkey(seeds[i])]

    # TODO also print params_id
    params, _ = session_params(hostpubkeys, t)

    async def session():
        coord_chans = CoordinatorChannels(n)
        participant_chans = [
            ParticipantChannel(coord_chans.queues[i]) for i in range(n)
        ]
        coord_chans.set_participant_queues(
            [participant_chans[i].queue for i in range(n)]
        )
        coroutines = [coordinator(coord_chans, params)] + [
            participant(participant_chans[i], seeds[i], params) for i in range(n)
        ]
        return await asyncio.gather(*coroutines)

    outputs = asyncio.run(session())
    return outputs


def main():
    n = 5
    t = 3
    seeds = [random_bytes(32) for _ in range(n)]

    # TODO Move more steps into the async methods. It's not an issue for the
    # tests to have prints in the async methods, we can suppress them, see
    # https://stackoverflow.com/a/28321717.
    print("=== Inputs ===")
    print(f"t: {t}")
    print(f"n: {n}")
    for i in range(n):
        print(f"Participant {i}'s seed:", seeds[i].hex())
    print()

    rets = simulate_chilldkg_full(seeds, t)
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
    print(recovery_data.hex())


if __name__ == "__main__":
    sys.exit(main())
