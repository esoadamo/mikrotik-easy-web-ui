import os
from threading import Lock, get_ident, Thread
from time import sleep, time
from queue import Queue
from typing import TypedDict, Dict, Optional, Tuple, Set, NamedTuple, Any
from sys import stderr

from routeros_api.api import RouterOsApi, RouterOsApiPool
from routeros_api.exceptions import RouterOsApiError
from routeros_api.resource import RouterOsResource
from dotenv import load_dotenv

load_dotenv()

API_SLEEP_TIME = float(os.getenv('API_SLEEP_TIME', '0'))


class APICredentials(NamedTuple):
    username: str
    password: str
    address: str


class APIMultithread:
    class CacheContent(TypedDict):
        last_heartbeat_check: int
        api: RouterOsApi
        conn: RouterOsApiPool
        lock: Lock

    __thread_cache: Dict[int, CacheContent] = {}
    __cache_lock = Lock()
    __watchdog_running = False

    @classmethod
    def is_ready(cls) -> bool:
        return cls.__get_login_credentials() is not None

    @classmethod
    def get_address(cls) -> str:
        return cls.__get_login_credentials().address

    @staticmethod
    def __get_login_credentials() -> Optional[APICredentials]:
        username = os.getenv('ROUTER_USER')
        password = os.getenv('ROUTER_PASSWORD')
        address = os.getenv('ROUTER_ADDRESS')
        if not any((username, password, address)):
            return None
        return APICredentials(username=username, password=password, address=address)

    @classmethod
    def __create_new_connection(cls) -> Tuple[RouterOsApi, RouterOsApiPool]:
        username, password, address = cls.__get_login_credentials()
        conn = RouterOsApiPool(address,
                               username=username,
                               password=password,
                               use_ssl=True,
                               ssl_verify=False,
                               plaintext_login=True)
        return conn.get_api(), conn

    @classmethod
    def watchdog(cls) -> None:
        session_ttl_minutes = 100
        while True:
            sleep(max(session_ttl_minutes / 3, 0.5) * 60)
            with cls.__cache_lock:
                old_sessions: Set[int] = set()
                for session_id, data in cls.__thread_cache.items():
                    if time() - data['last_heartbeat_check'] > session_ttl_minutes * 60:
                        old_sessions.add(session_id)
                for session_id in old_sessions:
                    try:
                        cls.__thread_cache[session_id]['conn'].disconnect()
                    except RouterOsApiError:
                        pass
                    del cls.__thread_cache[session_id]

    @classmethod
    def watchdog_start(cls) -> None:
        if cls.__watchdog_running:
            return
        cls.__watchdog_running = True
        Thread(target=cls.watchdog, daemon=True).start()

    @classmethod
    def __get(cls) -> Tuple[RouterOsApi, Lock]:
        thread_id = get_ident()
        with cls.__cache_lock:
            if thread_id in cls.__thread_cache:
                if time() - cls.__thread_cache[thread_id]['last_heartbeat_check'] > 2 * 60:
                    cls.__thread_cache[thread_id]['last_heartbeat_check'] = int(time())
                    try:
                        api, conn = cls.__thread_cache[thread_id]['api'], cls.__thread_cache[thread_id]['conn']
                        api.get_resource('/system/resource').get()
                    except RouterOsApiError:
                        try:
                            conn.disconnect()
                            if API_SLEEP_TIME:
                                sleep(API_SLEEP_TIME)
                        except RouterOsApiError:
                            pass
                        del cls.__thread_cache[thread_id]
            if thread_id not in cls.__thread_cache:
                api, conn = cls.__create_new_connection()
                cls.__thread_cache[thread_id] = {
                    'api': api,
                    'conn': conn,
                    'last_heartbeat_check': time(),
                    'lock': Lock()
                }

            return cls.__thread_cache[thread_id]['api'], cls.__thread_cache[thread_id]['lock']

    @classmethod
    def disconnect(cls):
        with cls.__cache_lock:
            for data in cls.__thread_cache.values():
                data['conn'].disconnect()
                if API_SLEEP_TIME:
                    sleep(API_SLEEP_TIME)
            for key in list(cls.__thread_cache.keys()):
                del cls.__thread_cache[key]

    @classmethod
    def call(cls, path: str) -> RouterOsResource:
        api, lock = cls.__get()
        return api.get_resource(path)


class APISingleThreadPath:
    def __init__(self, path: str, queue_in: Queue, queue_out: Queue, lock_command: Lock):
        self.__path = path
        self.__queue_in = queue_in
        self.__queue_out = queue_out
        self.__lock_command = lock_command
        self.__wait_time = 0.0

    @property
    def wait_time(self) -> float:
        return self.__wait_time

    def __call(self, action: str, args: Tuple[Any] = (), kwargs: Optional[Dict[str, Any]] = None) -> Any:
        kwargs = kwargs or {}
        command = APISingleTreadWorkerCommand(
            action=action,
            args=args,
            kwargs=kwargs,
            path=self.__path
        )
        time_start = time()
        with self.__lock_command:
            self.__queue_in.put(command)
            self.__wait_time = time() - time_start
            output = self.__queue_out.get()
            if isinstance(output, Exception):
                raise output
            return output

    def get(self, *args, **kwargs) -> Any:
        return self.__call('get', args, kwargs)

    def remove(self, *args, **kwargs) -> Any:
        return self.__call('remove', args, kwargs)

    def set(self, *args, **kwargs) -> Any:
        return self.__call('set', args, kwargs)

    def exec(self,
             command: str,
             arguments: Optional[Dict[str, Any]] = None,
             queries: Optional[Dict[str, Any]] = None
             ) -> Any:
        kwargs = {}

        if arguments:
            kwargs['arguments'] = arguments
        if queries:
            kwargs['queries'] = queries
        return self.__call('call', args=(command,), kwargs=kwargs)


class APISingleTreadWorkerCommand(NamedTuple):
    path: str
    action: str
    args: Tuple[Any]
    kwargs: Dict[str, Any]


class APISingleTreadWorker(Thread):
    def __init__(
            self,
            queue_in: "Queue[APISingleTreadWorkerCommand]",
            queue_out: "Queue[Any]",
    ):
        self.__queue_in = queue_in
        self.__queue_out = queue_out
        super().__init__(daemon=True)

    def run(self) -> None:
        while True:
            try:
                command = self.__queue_in.get()
                print("[CALL]", command.path, command.action, command.args, command.kwargs, file=stderr)
                resource = APIMultithread.call(command.path)
                output = resource.__getattribute__(command.action)(*command.args, **command.kwargs)
                # print('... ', output, file=stderr)
                self.__queue_out.put(output)
                if API_SLEEP_TIME:
                    sleep(API_SLEEP_TIME)
            except Exception as e:
                self.__queue_out.put(e)


class APISingleTread:
    def __init__(self):
        self.__queue_in: Queue[APISingleTreadWorkerCommand] = Queue(1)
        self.__queue_out: Queue[Any] = Queue(1)
        self.__lock_command = Lock()
        APISingleTreadWorker(self.__queue_in, self.__queue_out).start()
        APIMultithread.watchdog_start()

    @property
    def address(self) -> str:
        return APIMultithread.get_address()

    @property
    def is_ready(self) -> bool:
        return APIMultithread.is_ready()

    def call(self, path: str) -> APISingleThreadPath:
        return APISingleThreadPath(path, self.__queue_in, self.__queue_out, self.__lock_command)


API = APISingleTread()
