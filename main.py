import json
import re
import os
import requests
import traceback
from datetime import datetime
from hashlib import md5
from pathlib import Path
from queue import Queue
from random import randint
from subprocess import call, PIPE
from threading import Thread, Lock
from time import sleep
from time import time
from types import SimpleNamespace
from typing import List, Tuple, Optional, Dict, Union, Callable, Any, Set, Iterable
from uuid import uuid4 as uuid
from dotenv import load_dotenv
from flask import Flask, Response, render_template, redirect, url_for, request
from routeros_api import RouterOsApiPool
from routeros_api.api import RouterOsApi

try:
    import notification
except ImportError:
    notification = None

load_dotenv()

CachedRequestActiveClientsCache = List[Tuple[str, Optional[str], bool]]
CachedRequestNetUsageByIPCache = Dict[str, Tuple[int, int]]
RequestLimits = List[Tuple[str, str, float, float, Optional[int]]]


class CachedRequest(SimpleNamespace):
    cache: Union[CachedRequestActiveClientsCache, CachedRequestNetUsageByIPCache]
    nextRequestTime: float
    nextRequestDelay: float
    lock: Lock


CACHE: Dict[str, CachedRequest] = {
    'clients': CachedRequest(
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

ROUTER_ADDRESS = os.getenv('ROUTER_ADDRESS')
LOCAL_NETWORK = os.getenv('LOCAL_NETWORK')
WEB_PORT = os.getenv('WEB_UI_PORT')
DoH_SERVER = os.getenv('AUTO_DoH_SERVER')
FILE_ROUTER_LOG = Path(os.getenv('ROUTER_LOG'))
LOCK_ROUTER_LOG = Lock()
FILE_SELF_LOG = Path(os.getenv('LOG'))
SELF_LOG_QUEUE = Queue(maxsize=2048)


def rt(data: any) -> Response:
    return Response(json.dumps(data), mimetype='application/json')


def get_login_credentials() -> Optional[Tuple[str, str]]:
    username = os.getenv('ROUTER_USER')
    password = os.getenv('ROUTER_PASSWORD')
    if not username or not password:
        return None
    return username, password


def get_api() -> Tuple[RouterOsApi, RouterOsApiPool]:
    username, password = get_login_credentials()
    conn = RouterOsApiPool(ROUTER_ADDRESS,
                           username=username,
                           password=password,
                           use_ssl=True,
                           ssl_verify=False,
                           plaintext_login=True)
    return conn.get_api(), conn


def retry_on_error(f: Callable) -> Callable:
    def i() -> Any:
        while True:
            # noinspection PyBroadException
            try:
                return f()
            except Exception:
                exc = traceback.format_exc()
                log('[ERROR] Retrying')
                log('[TRACEBACK]', exc.replace('\n', '\n           '))
                sleep(60)

    return i


def ping(host: str) -> bool:
    try:
        return call(['ping', '-c', '3', host], timeout=300, stdout=PIPE, stdin=PIPE, stderr=PIPE) == 0
    except TimeoutError:
        return False


def is_dns_healthy() -> bool:
    return (not ping("1.1.1.1") and not ping("8.8.8.8")) or ping(f"{uuid().hex}.local.devmonthor.eu")


def set_doh_enabled(enabled: bool) -> None:
    api, conn = get_api()
    if enabled:
        api.get_resource('/ip/dns').call('set', arguments={'use-doh-server': DoH_SERVER,
                                                           'verify-doh-cert': 'yes',
                                                           'servers': ''})
    else:
        api.get_resource('/ip/dns').call('set', arguments={'use-doh-server': '',
                                                           'servers': '1.1.1.1,1.0.0.1,8.8.8.8,8.4.4.8'})
    conn.disconnect()


def limit_get_names() -> Iterable[str]:
    api, conn = get_api()
    r = map(lambda x: x['name'], api.get_resource('/queue/simple').get())
    conn.disconnect()
    return r


def limit_remove(name: str) -> None:
    api, conn = get_api()
    limits = api.get_resource('/queue/simple')
    limit_id = limits.get(name=name)[0]['id']
    limits.remove(id=limit_id)
    conn.disconnect()


def limit_add(name: str, target: str, upload: float, download: float) -> None:
    """
    :param name: name of the queue
    :param target: IP address, /32 is added
    :param upload: in MiB
    :param download: in MiB
    :return: None
    """
    for existing_limit_name in limit_get_names():
        if existing_limit_name == name or existing_limit_name.startswith(f"_{target}"):
            limit_remove(existing_limit_name)
            break
    api, conn = get_api()
    api.get_resource('/queue/simple').call('add', arguments={
        'name': name,
        'target': f"{target}/32" if target != "EVERYONE" else LOCAL_NETWORK,
        'max-limit': "%.2fM/%.2fM" % (upload * 8, download * 8)
    })
    conn.disconnect()


def limits_fetch() -> RequestLimits:
    api, conn = get_api()
    r: RequestLimits = []
    for limit in api.get_resource('/queue/simple').get():
        name: str = limit.get('name')
        if not name.startswith('_'):
            continue
        _, target, timeout = name.split('_')
        upload, download = limit.get('max-limit').split('/')
        timeout = int(timeout) if timeout != 'EVER' else None
        r.append((name, str(target), int(download) / 8000000, int(upload) / 8000000, timeout))
    conn.disconnect()
    return r


def log(*args) -> None:
    date = datetime.now().strftime("%Y/%m/%d %H:%M:%S")
    line = ' '.join([str(x) for x in args])
    line_offset = " " * (len(date) + 1)

    line = line.replace('\n', '\n' + line_offset)

    line = f"{date}: {line}"
    print(line)
    SELF_LOG_QUEUE.put(line)


@retry_on_error
def get_updates_available() -> bool:
    api, conn = get_api()
    res = api.get_resource('/system/package/update').call('check-for-updates')
    conn.disconnect()
    return 'available' in res[-1]['status'].lower()


@retry_on_error
def get_log() -> List[Dict[str, str]]:
    api, conn = get_api()
    res = api.get_resource('/log').get()
    conn.disconnect()
    return res


@retry_on_error
def get_sniffer_running() -> bool:
    api, conn = get_api()
    r = api.get_resource('/tool/sniffer').get()[0]['running'] == 'true'
    conn.disconnect()
    return r


@retry_on_error
def get_clients() -> CachedRequestActiveClientsCache:
    api, conn = get_api()
    res = api.get_resource('/ip/dhcp-server/lease').get()
    conn.disconnect()
    r: List[Tuple[str, Optional[str], bool]] = []
    for client in res:
        if client.get('address', '') == '10.1.1.1':
            continue
        r.append((client.get('address'), client.get('comment'), client.get('status', '') == 'bound'))
    return r


@retry_on_error
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

    router_ip = ROUTER_ADDRESS
    server_ip = os.getenv('LOCAL_ADDRESS')
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
def web_index() -> Response:
    return redirect(url_for('web_root'))


@app.route('/net/')
def web_root() -> Response:
    return render_template('index.html')


@app.route('/net/api/clients')
def api_clients() -> Response:
    entry = CACHE['clients']
    time_to_next_request = entry.nextRequestTime - time()
    lock: Lock = entry.lock
    if time_to_next_request < 0 and lock.acquire(blocking=False):
        if entry.nextRequestTime and time_to_next_request < -5 * 60:
            entry.nextRequestDelay = 30
        else:
            entry.nextRequestDelay = min(entry.nextRequestDelay + 0.2 + randint(0, 10) / 10, 60)
        entry.nextRequestTime = int(time()) + entry.nextRequestDelay

        def job():
            try:
                entry.cache = get_clients()
            finally:
                lock.release()

        Thread(target=job, daemon=True).start()

    return rt(entry.cache)


@app.route('/net/api/net-usage-by-ip')
def api_net_usage_by_ip() -> Response:
    entry = CACHE['net-usage-by-ip']
    time_to_next_request = entry.nextRequestTime - time()
    lock: Lock = entry.lock
    if time_to_next_request < 0 and lock.acquire(blocking=False):
        if entry.nextRequestTime and time_to_next_request < -5 * 60:
            entry.nextRequestDelay = 5
        else:
            entry.nextRequestDelay = min(entry.nextRequestDelay + 0.5 + randint(0, 20) / 10, 30)
        entry.nextRequestTime = int(time()) + entry.nextRequestDelay

        def job():
            try:
                entry.cache = get_net_usage_by_ip()
            finally:
                lock.release()

        Thread(target=job, daemon=True).start()
    return rt(entry.cache)


@app.route('/net/api/new-limit', methods=['POST'])
def api_new_limit() -> Response:
    target = request.form.get('target')
    if not target:
        return rt({'error': 'No target specified'})
    upload = max(float(request.form.get('upload')), 0.1)
    download = max(float(request.form.get('download')), 0.1)
    until_date = request.form.get('date')
    until_time = request.form.get('time')

    if not until_date and not until_time:
        ttl = 'EVER'
    elif not until_time and until_date:
        ttl = str(int(datetime.strptime(until_date, '%Y-%m-%d').timestamp()))
    elif until_time and not until_date:
        hours, minutes = until_time.split(':')
        ttl = str(int(datetime.now().replace(hour=0, minute=0).timestamp() + (int(hours) * 3600) + (int(minutes) * 60)))
    else:
        ttl = str(int(datetime.strptime(f"{until_date} {until_time}", '%Y-%m-%d %H:%M').timestamp()))

    limit_add(f"_{target}_{ttl}", target, upload, download)

    return redirect(url_for('web_root'))


@app.route('/net/api/limit-remove', methods=['POST'])
def api_limit_remove() -> Response:
    name = request.form.get('name')
    assert name
    limit_remove(name)
    return redirect(url_for('web_root'))


@app.route('/net/api/limits')
def api_limits() -> Response:
    return rt(limits_fetch())


def send_notification(msg: str) -> bool:
    if notification is not None:
        return False
    return notification.send_notification(msg)


@retry_on_error
def thread_stop_sniffer() -> None:
    while True:
        if CACHE['net-usage-by-ip'].nextRequestTime > 0 and \
                CACHE['net-usage-by-ip'].nextRequestTime - time() < -600 and get_sniffer_running():
            api, conn = get_api()
            api.get_resource('/tool/sniffer').call('stop')
            conn.disconnect()
        sleep((5 + randint(0, 10)) * 60)


@retry_on_error
def thread_check_updates() -> None:
    while True:
        if get_updates_available():
            send_notification('Router updates available')
        sleep((24 + randint(0, 24)) * 3600)


@retry_on_error
def thread_notif_logged_errors() -> None:
    message_hashes: Set[str] = set()
    first_load = True
    while True:
        message_hashes_curr: Set[str] = set()
        for rec in get_log():
            rec_time: str = rec.get('time', '')
            rec_message: str = rec.get('message', '')

            rec_hash_input = (rec_message + (rec_time if ' ' not in rec_time else rec_time.split(' ', 1)[1]))
            rec_hash: str = md5(rec_hash_input.encode('utf8')).hexdigest()
            rec_id = int(rec.get('id', '*-1')[1:], 16)
            message_hashes_curr.add(rec_hash)
            if rec_hash in message_hashes or first_load:
                continue
            topics: List[str] = rec.get('topics', '').split(',')

            if FILE_ROUTER_LOG and FILE_ROUTER_LOG.is_dir():
                with LOCK_ROUTER_LOG:
                    try:
                        with FILE_ROUTER_LOG.open('a') as f:
                            rec_log_data = {'timestamp': int(time())}
                            rec_log_data.update(rec)
                            f.write(json.dumps(rec_log_data) + '\n')
                    except PermissionError:
                        log('[FATAL] [LOG] cannot write log to a file')

            if 'error' not in topics:
                continue
            if 'DoH server connection error: ' in rec_message:
                continue

            message = f"Router error {rec_id} @ {rec_time}: {rec_message}"
            log("[LOG]", message)
            send_notification(message)
        message_hashes = message_hashes_curr
        first_load = False
        sleep(600 + randint(0, 600))


@retry_on_error
def thread_test_dns() -> None:
    while True:
        if not is_dns_healthy():
            log('[DNS HEALTH] Restoring DNS')
            set_doh_enabled(False)

            sleep(5 * 60)
            if not is_dns_healthy():
                sleep(30)
                continue

            set_doh_enabled(True)

        sleep(30)


@retry_on_error
def thread_check_cpu() -> None:
    while True:
        # noinspection HttpUrlsUsage
        html = requests.get(f'http://{ROUTER_ADDRESS}/graphs/cpu/', timeout=60).text
        for r in re.finditer(r'Max:\s+[0-9]+%;\s+Average:\s+[0-9]+%;\s+Current:\s+([0-9]+)%', html, re.I):
            current_usage = int(r.group(1))
            if current_usage > 65:
                msg = f"High router CPU usage ({current_usage}%)"
                log("[CPU]", msg)
                send_notification(msg)
            break
        sleep(5 * 60 + randint(30, 50))


@retry_on_error
def thread_remove_old_limits() -> None:
    while True:
        limits_to_remove: List[str] = []
        for limit in limits_fetch():
            limit_name = limit[0]
            limit_timeout = limit[4]
            if limit_timeout and limit_timeout < time():
                limits_to_remove.append(limit_name)
        for limit_name in limits_to_remove:
            limit_remove(limit_name)
        sleep(60 + randint(30, 50))


@retry_on_error
def thread_write_log() -> None:
    while True:
        line = SELF_LOG_QUEUE.get()
        if not FILE_SELF_LOG or FILE_SELF_LOG.is_dir():
            continue
        try:
            with FILE_SELF_LOG.open('a') as f:
                f.write(line + '\n')
        except PermissionError:
            print(f'[LOG] Fatal: Cannot access log file "{FILE_SELF_LOG}"')


def main() -> int:
    log("[MAIN] starting up")
    if not get_login_credentials():
        log("[MAIN] Error: Login credentials are missing!")
        return 1
    if not WEB_PORT or not LOCAL_NETWORK or not ROUTER_ADDRESS:
        log("[MAIN] Error: Some required settings are missing")
        return 1
    Thread(target=thread_notif_logged_errors, daemon=True).start()
    Thread(target=thread_check_updates, daemon=True).start()
    Thread(target=thread_stop_sniffer, daemon=True).start()
    Thread(target=thread_check_cpu, daemon=True).start()
    Thread(target=thread_write_log, daemon=True).start()
    Thread(target=thread_remove_old_limits, daemon=True).start()
    if DoH_SERVER is not None:
        set_doh_enabled(True)
        Thread(target=thread_test_dns, daemon=True).start()
    app.run(port=int(WEB_PORT))
    return 0


if __name__ == '__main__':
    exit(main())
