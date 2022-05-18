from threading import Thread
from time import sleep, time
from collections import deque
from typing import Iterator, Set, Tuple, NamedTuple, List, Optional, Dict, TypeVar, Generic

from dotenv import load_dotenv

from router_api import API

load_dotenv()

T = TypeVar('T')


class Limit(NamedTuple):
    id: Optional[str]
    ip: int
    rate: int
    max_rate: int


class DictAverage(Generic[T]):
    def __init__(self, n: int) -> None:
        self.__n = n
        self.__data: Dict[T, deque[float]] = {}

    def __setitem__(self, key: T, value: float) -> None:
        if key not in self.__data:
            self.__data[key] = deque()
        self.__data[key].append(value)
        if len(self.__data[key]) > self.__n:
            self.__data[key].popleft()

    def __getitem__(self, item: T) -> float:
        data = self.__data[item]
        return sum(data) / self.__n

    def __iter__(self) -> Iterator[Tuple[T, float]]:
        return map(
            lambda x: (x, self[x]),
            self.__data.keys()
        )


class Balancer(Thread):
    def __init__(self, ip_prefix: str, max_bandwitch: int, min_bandwitch: int, threshold: int = 95,
                 api: API = API()) -> None:
        super().__init__()
        self.__max_bandwitch = max_bandwitch
        self.__min_bandwitch = min_bandwitch
        self.__threshold = threshold / 100
        self.__ip_prefix = ip_prefix
        self.__name_prefix = f"balancer_{self.__ip_prefix}"
        self.__api: API = api
        self.__get_queues_history: DictAverage[int] = DictAverage(n=2)

        self.__mark_cache: Dict[int, int] = {}
        self.__mark_cache_time: int = 0

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

        for i in range(1, 255):
            ip, mark_name = self.__ip_mark_name(i)
            if mark_name in existing_marks:
                continue
            self.__api.call('ip/firewall/mangle').call('add', arguments={
                'chain': 'forward',
                'dst-address': f'{ip}/32' if i != 0 else f'{ip}/24',
                'src-address': f'!{self.__ip_prefix}.0/24',
                'action': 'mark-packet',
                'new-packet-mark': mark_name,
                'passthrough': 'no'
            })

    def __init_queues(self) -> None:
        queues = list(self.__get_queues(include_root=True))
        self.__create_queue(0, queues)
        for i in range(1, 255):
            self.__delete_queue(i, queues)

    def __create_queue(self, ip: int, queues: Optional[Iterator[Limit]] = None, limit_at: Optional[int] = None, max_limit: Optional[int] = None) -> None:
        queues = list(queues if queues else self.__get_queues(include_root=True))
        existing_ips: Set[int] = set(map(lambda x: x.ip, queues))

        ip_full, mark_name = self.__ip_mark_name(ip)
        _, parent_name = self.__ip_mark_name(0)
        if ip == 0:
            parent_name = 'bridge'

        if ip not in existing_ips:
            self.__api.call('queue/tree').call('add', arguments={
                'name': mark_name,
                'max-limit': '999M' if limit_at is None else str(limit_at),
                'limit-at': '999M' if max_limit is None else str(max_limit),
                'packet-mark': mark_name if ip != 0 else '',
                'parent': parent_name
            })

    def __delete_queue(self, ip: int, queues: Optional[Iterator[Limit]] = None) -> None:
        queues = list(queues if queues else self.__get_queues(include_root=True))
        _, mark_name = self.__ip_mark_name(ip)

        for q in queues:
            if q.ip != ip:
                continue
            if q.id is None:
                return
            self.__api.call('queue/tree').remove(id=q.id)
            return

    def __set_limit(self, ip: int, limit: int, queues: Optional[List[Limit]] = None) -> None:
        _, mark_name = self.__ip_mark_name(ip)
        limit_at = int(limit * self.__threshold)

        if queues is None:
            queue_data = self.__queue_data_to_limit(
                self.__api.call('queue/tree').call('print', queries={'name': mark_name})[0]
            )
        else:
            queue_data = next(filter(lambda x: x.ip == ip, queues))

        if queue_data.max_rate == limit:
            return

        print(f"[NEW LIMIT] {ip=} limit={limit / (1024 ** 2)}")
        if queue_data.id is not None:
            self.__api.call('queue/tree').set(id=queue_data.id, max_limit=str(limit), limit_at=str(limit_at))
        else:
            self.__create_queue(ip, queues, limit_at=limit_at, max_limit=limit)

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

    def __get_queues(self, existing: Optional[Iterator[Limit]] = None, include_root: bool = False) -> Iterator[Limit]:
        if existing is not None:
            yield from list(existing)
            return
        print('... get')
        time_start = time()
        marks = list(filter(
            lambda x: x.get('new-packet-mark', '').startswith(self.__name_prefix),
            self.__api.call('ip/firewall/mangle').call('print', arguments={'stats': ''})
        ))

        queues_map = {x.ip: x for x in map(
            self.__queue_data_to_limit,
            filter(
                lambda x: x['name'].startswith(self.__name_prefix) and (include_root or not x['name'].endswith('.000')),
                self.__api.call('queue/tree').call('print', arguments={'stats': ''})
            )
        )}

        if include_root:
            q_root = queues_map.get(0)
            if q_root:
                yield q_root

        time_delta = time_start - self.__mark_cache_time
        for m in marks:
            ip = int(m['new-packet-mark'].rsplit('.', 1)[1])
            m_bytes = int(m['bytes'])
            if ip in queues_map:
                yield queues_map[ip]
            if ip in self.__mark_cache:
                bytes_delta = m_bytes - self.__mark_cache[ip]
                rate = int(8 * bytes_delta / time_delta)
                yield Limit(
                    id=None,
                    ip=ip,
                    rate=rate,
                    max_rate=self.__max_bandwitch
                )
            self.__mark_cache[ip] = m_bytes
        self.__mark_cache_time = time_start

    def __get_queue_root(self, queues: Optional[Iterator[Limit]] = None) -> Limit:
        queues = self.__get_queues(queues)

        for q in queues:
            if q.ip == 0:
                return q
        raise ValueError("Root queue not found")

    def __get_queues_limited(self, queues: Optional[Iterator[Limit]] = None) -> Iterator[Limit]:
        queues = self.__get_queues(queues)

        return filter(
            lambda x: x.max_rate < self.__max_bandwitch,
            queues
        )

    def __get_queues_full(self, queues: Optional[Iterator[Limit]] = None) -> Iterator[Limit]:
        queues = self.__get_queues(queues)

        return filter(
            lambda x: x.rate > x.max_rate * self.__threshold,
            self.__get_queues_limited(queues)
        )

    def __get_queues_used(self, queues: Optional[Iterator[Limit]] = None) -> Iterator[Limit]:
        queues = list(self.__get_queues(queues))

        return filter(
            lambda x: x.rate > 0,
            queues
        )

    def __get_queues_used_unlimited(self, queues: Optional[Iterator[Limit]] = None) -> Iterator[Limit]:
        queues = self.__get_queues(queues)
        queues_limited_ips: Set[int] = set(map(lambda x: x.ip, self.__get_queues_limited(queues)))

        return filter(
            lambda x: x.ip not in queues_limited_ips,
            self.__get_queues_used(queues)
        )

    def __get_queues_used_limited(self, queues: Optional[Iterator[Limit]] = None) -> Iterator[Limit]:
        queues = self.__get_queues(queues)
        queues_limited_ips: Set[int] = set(map(lambda x: x.ip, self.__get_queues_limited(queues)))

        return filter(
            lambda x: x.ip in queues_limited_ips,
            self.__get_queues_used(queues)
        )

    def run(self) -> None:
        while True:
            queues = list(self.__get_queues())
            queues_used_unlimited = list(self.__get_queues_used_unlimited(queues))
            queues_used_limited = list(self.__get_queues_used_limited(queues))
            queues_limited = list(self.__get_queues_limited(queues))
            queues_limited_full = list(self.__get_queues_full(queues))

            print(list(self.__get_queues_used(queues)))
            print(f"{queues_used_limited=}")
            print(f"{queues_used_unlimited=}")

            for q in queues:
                if q.ip == 0:
                    continue
                self.__get_queues_history[q.ip] = q.rate

            bandwitch_used = sum(map(lambda x: x[1], self.__get_queues_history))
            bandwitch_free = (self.__max_bandwitch * self.__threshold) - bandwitch_used
            print(f"{bandwitch_free / (1024 ** 2)}")

            if bandwitch_free > 0:
                queues_to_extend = queues_limited if not queues_limited_full else queues_limited_full
                if queues_to_extend:
                    bandwitch_add = bandwitch_free / len(queues_to_extend)
                    for q in queues_limited_full:
                        self.__set_limit(q.ip, min(q.max_rate + bandwitch_add, self.__max_bandwitch), queues)
            else:
                for q in queues_used_unlimited:
                    self.__set_limit(q.ip, self.__min_bandwitch, queues)
                if queues_used_limited:
                    new_bandwitch = max(int(self.__max_bandwitch / len(queues_used_limited)), self.__min_bandwitch)
                    for q in queues_used_limited:
                        self.__set_limit(q.ip, new_bandwitch, queues)

            sleep(5)


if __name__ == '__main__':
    def main() -> None:
        b = Balancer('10.1.1', 10 * (1024 ** 2), 3 * (1024 ** 2))
        b.start()


    main()
