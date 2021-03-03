import json
import traceback
import re
from datetime import datetime
from queue import Queue
from random import randint
from threading import Thread, Lock
from time import time
from typing import List, Tuple, Optional, Dict, Union, Callable, Any, Set
from types import SimpleNamespace
from time import sleep
from subprocess import call, PIPE
from uuid import uuid4 as uuid
from hashlib import md5

import requests
from flask import Flask, Response, render_template
from routeros_api import RouterOsApiPool
from routeros_api.api import RouterOsApi
from routeros_api.exceptions import RouterOsApiError, RouterOsApiConnectionError, RouterOsApiCommunicationError
from routeros_api.exceptions import RouterOsApiConnectionClosedError, RouterOsApiFatalCommunicationError
from pathlib import Path

CachedRequestActiveClientsCache = List[Tuple[str, Optional[str]]]
CachedRequestNetUsageByIPCache = Dict[str, Tuple[int, int]]


class CachedRequest(SimpleNamespace):
    cache: Union[CachedRequestActiveClientsCache, CachedRequestNetUsageByIPCache]
    nextRequestTime: float
    nextRequestDelay: float
    lock: Lock


CACHE: Dict[str, CachedRequest] = {
    'active-clients': CachedRequest(
      cache=[],
      nextRequestTime=0.0,
      nextRequestDelay=0.0,
      lock=Lock()
    ),
    'net-usage-by-ip': CachedRequest(
      cache={},
      nextRequestTime=0.0,
      nextRequestDelay=0.0,
      lock=Lock()
    ),
}

app = Flask(__name__, static_folder='static', template_folder='html')

ROUTER_ADDRESS = '10.1.1.1'
FILE_ROUTER_LOG = Path('/var/log/router.log')
LOCK_ROUTER_LOG = Lock()
FILE_SELF_LOG = Path('/var/log/router_api.log')
SELF_LOG_QUEUE = Queue(maxsize=2048)


def rt(data: any) -> Response:
    return Response(json.dumps(data), mimetype='application/json')


def get_api() -> Tuple[RouterOsApi, RouterOsApiPool]:
    conn = RouterOsApiPool(ROUTER_ADDRESS,
                           username='api',
                           password=r"""12df4c479a4189367aba29e1eb74983479b15440ae321115626806fbd9858915""",
                           use_ssl=True,
                           ssl_verify=False,
                           plaintext_login=True)
    return conn.get_api(), conn


def retry_on_routeros_error(f: Callable) -> Callable:
    def i() -> Any:
        while True:
            try:
                return f()
            except (RouterOsApiError, RouterOsApiConnectionError, RouterOsApiConnectionError,
                    RouterOsApiFatalCommunicationError, RouterOsApiCommunicationError,
                    RouterOsApiConnectionClosedError):
                traceback.print_exc()
                log('[RouterOS ERROR] Retrying')
                sleep(60)

    return i


def ping(host: str) -> bool:
    try:
        return call(['ping', '-c', '3', host], timeout=300, stdout=PIPE, stdin=PIPE, stderr=PIPE) == 0
    except TimeoutError:
        return False


def is_dns_healthy() -> bool:
    return ping(f"{uuid().hex}.local.devmonthor.eu")


def log(*args) -> None:
    date = datetime.now().strftime("%Y/%m/%d %H:%M:%S")
    line = f"{date}: {' '.join([str(x) for x in args])}"
    print(line)
    SELF_LOG_QUEUE.put(line)


@retry_on_routeros_error
def get_updates_available() -> bool:
    api, conn = get_api()
    res = api.get_resource('/system/package/update').call('check-for-updates')
    conn.disconnect()
    return 'available' in res[-1]['status'].lower()


@retry_on_routeros_error
def get_log() -> List[Dict[str, str]]:
    api, conn = get_api()
    res = api.get_resource('/log').get()
    conn.disconnect()
    return res


@retry_on_routeros_error
def get_sniffer_running() -> bool:
    api, conn = get_api()
    r = api.get_resource('/tool/sniffer').get()[0]['running'] == 'true'
    conn.disconnect()
    return r


@retry_on_routeros_error
def get_active_clients() -> CachedRequestActiveClientsCache:
    api, conn = get_api()
    res = api.get_resource('/ip/dhcp-server/lease').get()
    conn.disconnect()
    r: List[Tuple[str, Optional[str]]] = []
    for client in res:
        if client.get('address', '') == '10.1.1.1' or client.get('status', '') != 'bound':
            continue
        r.append((client.get('address'), client.get('comment')))
    return r


@retry_on_routeros_error
def get_net_usage_by_ip() -> CachedRequestNetUsageByIPCache:
    api, conn = get_api()
    ip_speed: Dict[str, Tuple[int, int]] = {}
    if not get_sniffer_running():
        api.get_resource('/tool/sniffer').call('start')
    packets = api.get_resource('/tool/sniffer/host').get()
    conn.disconnect()
    for packet in packets:
        ip_from: str = packet.get('address', '')
        speed: Tuple[str, str] = tuple(packet.get('rate', '0/0').split('/'))
        if not ip_from.startswith('10.'):
            continue
        speed_down, speed_up = int(speed[0]) // (8 * 1024), int(speed[1]) // (8 * 1024)
        if speed_up + speed_down == 0:
            continue
        ip_speed[ip_from] = (speed_down, speed_up)
        
    router_ip = '10.1.1.1'
    server_ip = '10.1.1.10'
    if router_ip in ip_speed and server_ip in ip_speed:
        router_down, router_up = ip_speed[router_ip]
        server_down, server_up = ip_speed[server_ip]
        ip_speed[server_ip] = (max(0, server_down - router_up), max(0, server_up - router_down))
        ip_speed[router_ip] = (max(0, router_up - server_down), max(0, router_down - server_up))
        for ip in (server_ip, router_ip):
            if sum(ip_speed[ip]) <= 0:
                del ip_speed[ip]

    return ip_speed


@app.route('/')
def web_root() -> Response:
    return render_template('index.html')


@app.route('/api/active-clients')
def api_active_clients() -> Response:
    entry = CACHE['active-clients']
    time_to_next_request = entry.nextRequestTime - time()
    lock: Lock = entry.lock
    if time_to_next_request < 0 and lock.acquire(blocking=False):
        if entry.nextRequestTime and time_to_next_request < -5 * 60:
            entry.nextRequestDelay = 2
        else:
            entry.nextRequestDelay = min(entry.nextRequestDelay + 0.2 + randint(0, 10) / 10, 10)
        entry.nextRequestTime = int(time()) + entry.nextRequestDelay

        def job():
            try:
                entry.cache = get_active_clients()
            finally:
                lock.release()

        Thread(target=job, daemon=True).start()

    return rt(entry.cache)


@app.route('/api/net-usage-by-ip')
def api_net_usage_by_ip() -> Response:
    entry = CACHE['net-usage-by-ip']
    time_to_next_request = entry.nextRequestTime - time()
    lock: Lock = entry.lock
    if time_to_next_request < 0 and lock.acquire(blocking=False):
        if entry.nextRequestTime and time_to_next_request < -5 * 60:
            entry.nextRequestDelay = 2
        else:
            entry.nextRequestDelay = min(entry.nextRequestDelay + 0.2 + randint(0, 10) / 10, 30)
        entry.nextRequestTime = int(time()) + entry.nextRequestDelay

        def job():
            try:
                entry.cache = get_net_usage_by_ip()
            finally:
                lock.release()

        Thread(target=job, daemon=True).start()
    return rt(entry.cache)


def send_notification(msg: str) -> bool:
    return requests.get('https://api.ahlava.cz/msg/' + msg, timeout=60).status_code == 200


@retry_on_routeros_error
def thread_stop_sniffer() -> None:
    while True:
        if CACHE['net-usage-by-ip'].nextRequestTime > 0 and \
                CACHE['net-usage-by-ip'].nextRequestTime - time() < -600 and get_sniffer_running():
            api, conn = get_api()
            api.get_resource('/tool/sniffer').call('stop')
            conn.disconnect()
        sleep((5 + randint(0, 10)) * 60)


@retry_on_routeros_error
def thread_check_updates() -> None:
    while True:
        if get_updates_available():
            send_notification('Router updates available')
        sleep((24 + randint(0, 24)) * 3600)


@retry_on_routeros_error
def thread_notif_logged_errors() -> None:
    message_hashes: Set[bytes] = set()
    first_load = True
    while True:
        message_hashes_curr: Set[bytes] = set()
        for rec in get_log():
            rec_time: str = rec.get('time', '')
            rec_message: str = rec.get('message', '')

            rec_hash: bytes = md5((rec_message + (rec_time if ' ' not in rec_time else rec_time.split(' ', 1)[1]))
                                  .encode('utf8')).digest()
            rec_id = int(rec.get('id', '*-1')[1:], 16)
            if rec_hash in message_hashes:
                continue
            message_hashes_curr.add(rec_hash)
            topics: List[str] = rec.get('topics', '').split(',')

            if not first_load and FILE_ROUTER_LOG.exists():
                with LOCK_ROUTER_LOG:
                    with FILE_ROUTER_LOG.open('a') as f:
                        rec_log_data = {'timestamp': int(time())}
                        rec_log_data.update(rec)
                        f.write(json.dumps(rec_log_data) + '\n')

            if 'error' not in topics:
                continue
            if 'DoH server connection error: ' in rec_message:
                continue
            if not first_load:
                message = f"Router error {rec_id} @ {rec_time}: {rec_message}"
                log("[LOG]", message, rec_hash.hex())
                send_notification(message)
        message_hashes = message_hashes_curr
        first_load = False
        sleep(600 + randint(0, 600))


@retry_on_routeros_error
def thread_test_dns() -> None:
    while True:
        if not is_dns_healthy():
            log('[DNS HEALTH] Restoring DNS')
            api, conn = get_api()
            api.get_resource('/ip/dns/cache').call('flush')
            api.get_resource('/ip/dns').call('set', arguments={'use-doh-server': ''})
            sleep(5)
            if not is_dns_healthy():
                conn.disconnect()
                sleep(30)
                continue
            api.get_resource('/ip/dns').call('set', arguments={'use-doh-server': 'https://cloudflare-dns.com/dns-query',
                                                               'verify-doh-cert': 'yes'})
            conn.disconnect()

        sleep((60 + randint(10, 120)) if is_dns_healthy() else 30)


def thread_check_cpu() -> None:
    while True:
        html = requests.get(f'http://{ROUTER_ADDRESS}/graphs/cpu/', timeout=60).text
        for r in re.finditer(r'Max:\s+[0-9]+%;\s+Average:\s+[0-9]+%;\s+Current:\s+([0-9]+)%', html, re.I):
            current_usage = int(r.group(1))
            if current_usage > 75:
                msg = f"High router CPU usage ({current_usage}%)"
                log("[CPU]", msg)
                send_notification(msg)
            break
        sleep(5 * 60 + randint(30, 50))


def thread_write_log() -> None:
    try:
        while True:
            line = SELF_LOG_QUEUE.get()
            with FILE_SELF_LOG.open('a') as f:
                f.write(line + '\n')
    except PermissionError:
        print(f'[LOG] Fatal: Cannot access log file "{FILE_SELF_LOG}"')


def main():
    log("[MAIN] starting up")
    Thread(target=thread_notif_logged_errors, daemon=True).start()
    Thread(target=thread_check_updates, daemon=True).start()
    Thread(target=thread_stop_sniffer, daemon=True).start()
    Thread(target=thread_test_dns, daemon=True).start()
    Thread(target=thread_check_cpu, daemon=True).start()
    Thread(target=thread_write_log, daemon=True).start()
    app.run(port=8341)


if __name__ == '__main__':
    main()
