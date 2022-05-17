from threading import Thread
from time import sleep
from typing import Iterator, Set, Tuple, NamedTuple, List, Optional

from dotenv import load_dotenv

from router_api import API

load_dotenv()


class Limit(NamedTuple):
    id: str
    ip: int
    rate: int
    max_rate: int


class Balancer(Thread):
    def __init__(self, ip_prefix: str, max_bandwitch: int, threshold: int = 95, api: API = API()) -> None:
        super().__init__()
        self.__max_bandwitch = max_bandwitch
        self.__threshold = threshold / 100
        self.__ip_prefix = ip_prefix
        self.__api: API = api
        self.__init_marks()
        self.__init_queues()

    def __init_marks(self) -> None:
        existing_marks: Set[str] = set(map(
            lambda x: x['new-packet-mark'],
            filter(
                lambda x: x.get('new-packet-mark'),
                self.__api.call('ip/firewall/mangle').get()
            )
        ))

        for i in range(1, 256):
            ip, mark_name = self.__ip_mark_name(i)
            if mark_name in existing_marks:
                continue
            self.__api.call('ip/firewall/mangle').call('add', arguments={
                'chain': 'forward',
                'dst-address': f'{ip}/32' if i != 0 else f'{ip}/24',
                'action': 'mark-packet',
                'new-packet-mark': mark_name
            })

    @property
    def __max_limit(self) -> int:
        return int(self.__max_bandwitch * self.__threshold)

    def __init_queues(self) -> None:
        queues = list(self.__queues)
        existing_ips: List[int] = list(map(lambda x: x.ip, queues))
        for i in range(256):
            ip, mark_name = self.__ip_mark_name(i)
            _, parent_name = self.__ip_mark_name(0)
            if i == 0:
                parent_name = 'bridge'

            if i not in existing_ips:
                self.__api.call('queue/tree').call('add', arguments={
                    'name': mark_name,
                    'max-limit': '999M',
                    'limit-at': '999M',
                    'packet-mark': mark_name,
                    'parent': parent_name
                })

            if i != 0:
                self.__set_limit(i, self.__max_bandwitch, queues)

    def __set_limit(self, ip: int, limit: int, queues: Optional[List[Limit]] = None) -> None:
        _, mark_name = self.__ip_mark_name(ip)
        max_limit = str(limit)
        limit_at = str(int(limit * self.__threshold))

        if queues is None:
            queue_data = self.__queue_data_to_limit(
                self.__api.call('queue/tree').call('print', queries={'name': mark_name})[0]
            )
        else:
            queue_data = next(filter(lambda x: x.ip == ip, queues))

        if queue_data.max_rate == max_limit:
            return

        self.__api.call('queue/tree').set(id=queue_data.id, max_limit=max_limit, limit_at=limit_at)

    def __ip_mark_name(self, ip: int) -> Tuple[str, str]:
        return f"{self.__ip_prefix}.{ip}", f"balancer_{self.__ip_prefix}.{ip:03}"

    @staticmethod
    def __queue_data_to_limit(data: dict) -> Limit:
        return Limit(
            id=data['id'],
            ip=int(data['name'].rsplit('.', 1)[1]),
            rate=int(data['rate']),
            max_rate=int(data['max-limit'])
        )

    @property
    def __queues(self) -> Iterator[Limit]:
        queues = self.__api.call('queue/tree').call('print', arguments={'stats': ''})
        return map(
            self.__queue_data_to_limit,
            filter(
                lambda x: x['name'].startswith(f"balancer_{self.__ip_prefix}"),
                queues
            )
        )

    def __get_queue_root(self, queues: Optional[Iterator[Limit]] = None) -> Limit:
        queues = list(queues if queues else self.__queues)

        for q in queues:
            if q.ip == 0:
                return q
        raise ValueError("Root queue not found")

    def __get_queues_limited(self, queues: Optional[Iterator[Limit]] = None) -> Iterator[Limit]:
        queues = list(queues if queues else self.__queues)

        return filter(
            lambda x: x.max_rate < self.__max_limit,
            queues
        )

    def __get_queues_used(self, queues: Optional[Iterator[Limit]] = None) -> Iterator[Limit]:
        queues = list(queues if queues else self.__queues)

        return filter(
            lambda x: x.rate > 0 and x.ip != 0,
            queues
        )

    def run(self) -> None:
        while True:
            print(list(self.__queues))
            sleep(5)


if __name__ == '__main__':
    Balancer('10.1.1', 30 * (1024 ** 2)).start()
