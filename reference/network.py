import asyncio


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
