import os
from threading import Lock, get_ident, Thread
from time import sleep, time
from typing import TypedDict, Dict, Optional, Tuple, Set, NamedTuple

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


class API:
    class CacheContent(TypedDict):
        last_heartbeat_check: int
        api: RouterOsApi
        conn: RouterOsApiPool
        lock: Lock

    __thread_cache: Dict[int, CacheContent] = {}
    __cache_lock = Lock()

    __sleep_command_lock = Lock()
    __sleep_login_lock = Lock()

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
        single_thread_lock = not not API_SLEEP_TIME
        try:
            if single_thread_lock:
                cls.__sleep_login_lock.acquire()
            username, password, address = cls.__get_login_credentials()
            conn = RouterOsApiPool(address,
                                   username=username,
                                   password=password,
                                   use_ssl=True,
                                   ssl_verify=False,
                                   plaintext_login=True)
            return conn.get_api(), conn
        finally:
            if single_thread_lock:
                def unlock_time():
                    sleep(API_SLEEP_TIME)
                    cls.__sleep_login_lock.release()

                Thread(target=unlock_time).start()

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
    def call(cls, path: str) -> RouterOsResource:
        single_thread_lock = not not API_SLEEP_TIME
        try:
            if single_thread_lock:
                cls.__sleep_command_lock.acquire()
            api, lock = cls.__get()
            with lock:
                return api.get_resource(path)
        finally:
            if single_thread_lock:
                def unlock_time():
                    sleep(API_SLEEP_TIME)
                    cls.__sleep_command_lock.release()

                Thread(target=unlock_time).start()
