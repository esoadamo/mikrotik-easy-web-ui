import json
from random import randint
from threading import Thread, Lock
from time import time
from typing import List, Tuple, Optional, Dict, Union
from types import SimpleNamespace
from time import sleep

import requests
from flask import Flask, Response, render_template
from routeros_api import RouterOsApiPool
from routeros_api.api import RouterOsApi

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
      nextRequest=0.0,
      delay=0.0,
      lock=Lock()
    ),
    'net-usage-by-ip': CachedRequest(
      cache={},
      nextRequest=0.0,
      delay=0.0,
      lock=Lock()
    ),
}

app = Flask(__name__, static_folder='static', template_folder='html')


def rt(data: any) -> Response:
    return Response(json.dumps(data), mimetype='application/json')


def get_api() -> Tuple[RouterOsApi, RouterOsApiPool]:
    conn = RouterOsApiPool('10.1.1.1',
                           username='api',
                           password=r"""12df4c479a4189367aba29e1eb74983479b15440ae321115626806fbd9858915""",
                           use_ssl=True,
                           ssl_verify=False,
                           plaintext_login=True)
    return conn.get_api(), conn


def get_updates_available() -> bool:
    api, conn = get_api()
    res = api.get_resource('/system/package/update').call('check-for-updates')
    conn.disconnect()
    return 'available' in res[-1]['status'].lower()


def get_log() -> List[Dict[str, str]]:
    api, conn = get_api()
    res = api.get_resource('/log').get()
    conn.disconnect()
    return res


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


def get_net_usage_by_ip() -> CachedRequestNetUsageByIPCache:
    api, conn = get_api()
    ip_speed: Dict[str, Tuple[int, int]] = {}
    if api.get_resource('/tool/sniffer').get()[0]['running'] != 'true':
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
            entry.nextRequestDelay = min(entry.nextRequestDelay + 0.2 + randint(0, 10) / 10, 30)
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
    return requests.get('https://api.ahlava.cz/msg/' + msg).status_code == 200


def thread_check_updates() -> None:
    while True:
        if get_updates_available():
            send_notification('Router updates available')
        sleep((24 + randint(0, 24)) * 3600)


def thread_notif_logged_errors() -> None:
    last_id = -1
    first_load = True
    while True:
        max_id = -1
        for rec in get_log():
            rec_id = int(rec.get('id', '*-1')[1:], 16)
            if rec_id <= last_id:
                continue
            max_id = max(rec_id, max_id)
            topics: List[str] = rec.get('topics', '').split(',')
            if 'error' not in topics:
                continue
            if not first_load:
                message = f"Router error {rec_id} @ {rec.get('time')}: {rec.get('message')}"
                send_notification(message)
        last_id = max_id
        first_load = False
        sleep(600 + randint(0, 600))


def main():
    Thread(target=thread_notif_logged_errors, daemon=True).start()
    Thread(target=thread_check_updates, daemon=True).start()
    app.run(port=8341)


if __name__ == '__main__':
    main()
