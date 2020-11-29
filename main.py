import json

from typing import List, Tuple, Optional, Dict
from time import sleep, time

from routeros_api import RouterOsApiPool
from routeros_api.api import RouterOsApi
from flask import Flask, Response, send_from_directory
from threading import Lock

CACHE = {
    'active-clients': [[], 0, Lock()],
    'net-usage-by-ip': [{}, 0, Lock()]
}

app = Flask(__name__)


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


def get_active_clients() -> List[Tuple[str, Optional[str]]]:
    api, conn = get_api()
    res = api.get_resource('/ip/dhcp-server/lease').get()
    conn.disconnect()
    r: List[Tuple[str, Optional[str]]] = []
    for client in res:
        if client.get('address', '') == '10.1.1.1' or client.get('status', '') != 'bound':
            continue
        r.append((client.get('address'), client.get('comment')))
    return r


def get_net_usage_by_ip() -> Dict[str, Tuple[int, int]]:
    api, conn = get_api()
    ip_speed: Dict[str, Tuple[int, int]] = {}
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
    return send_from_directory('html', 'index.html')


@app.route('/api/active-clients')
def api_active_clients() -> Response:
    lock: Lock = CACHE['active-clients'][2]
    if not lock.locked() and time() - CACHE['active-clients'][1] >= 2:
        lock.acquire()
        try:
            # noinspection PyTypeChecker
            CACHE['active-clients'][1] = time()
            # noinspection PyTypeChecker
            CACHE['active-clients'][0] = get_active_clients()
        finally:
            lock.release()
    return rt(CACHE['active-clients'][0])


@app.route('/api/net-usage-by-ip')
def api_net_usage_by_ip() -> Response:
    lock: Lock = CACHE['net-usage-by-ip'][2]
    if not lock.locked() and time() - CACHE['net-usage-by-ip'][1] >= 2:
        lock.acquire()
        try:
            # noinspection PyTypeChecker
            CACHE['net-usage-by-ip'][1] = time()
            # noinspection PyTypeChecker
            CACHE['net-usage-by-ip'][0] = get_net_usage_by_ip()
        finally:
            lock.release()
    return rt(CACHE['net-usage-by-ip'][0])


def main():
    app.run(port=8341)


if __name__ == '__main__':
    main()
