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
from threading import Thread, Lock, get_ident
from time import sleep
from time import time
from types import SimpleNamespace
from typing import List, Tuple, Optional, Dict, Union, Callable, Any, Set, Iterable, TypedDict
from uuid import uuid4 as uuid
from dotenv import load_dotenv
from flask import Flask, Response, render_template, redirect, url_for, request
from routeros_api.exceptions import RouterOsApiError
from routeros_api import RouterOsApiPool
from routeros_api.api import RouterOsApi
from gevent.pywsgi import WSGIServer
from flask_httpauth import HTTPBasicAuth
from routeros_api.resource import RouterOsResource

try:
    import notification as notification_module
except ImportError:
    notification_module = None

load_dotenv()

# active IP, saved name, is active?, active mac, saved mac
CachedRequestActiveClientsCache = List[Tuple[str, Optional[str], bool, str, Optional[str]]]

# IP, down, up
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
auth = HTTPBasicAuth()

ROUTER_ADDRESS = os.getenv('ROUTER_ADDRESS')
LOCAL_NETWORK = os.getenv('LOCAL_NETWORK')
WEB_PORT = os.getenv('WEB_UI_PORT')
DoH_SERVER = os.getenv('AUTO_DoH_SERVER')
DNS_TRUSTED_SERVERS = os.getenv('DNS_TRUSTED_SERVERS')
DNS_FALLBACK_SERVERS = os.getenv('DNS_FALLBACK_SERVERS')
FILE_ROUTER_LOG = Path(os.getenv('ROUTER_LOG')) if os.getenv('ROUTER_LOG') is not None else None
LOCK_ROUTER_LOG = Lock()
FILE_SELF_LOG = Path(os.getenv('LOG')) if os.getenv('LOG') is not None else None
DNS_MONITOR_DOMAINS_FILE = os.getenv('DNS_MONITOR_DOMAINS_FILE')
UI_USER: Optional[str] = os.getenv('UI_USER')
UI_PASSWORD: Optional[str] = os.getenv('UI_PASSWORD')
SELF_LOG_QUEUE = Queue(maxsize=2048)
FILE_ARP_WATCH_DB = os.getenv('ARP_WATCH_DB')
ARP_WATCH_INTERFACE = os.getenv('ARP_WATCH_INTERFACE')
ARP_AUTO_REMOVE_TIME = (60 * int(os.getenv('ARP_AUTO_REMOVE_TIME'))) if os.getenv('ARP_AUTO_REMOVE_TIME') is not None else None


class API:
    class CacheContent(TypedDict):
        last_heartbeat_check: int
        api: RouterOsApi
        conn: RouterOsApiPool
        lock: Lock

    __thread_cache: Dict[int, CacheContent] = {}
    __cache_lock = Lock()

    @classmethod
    def is_ready(cls) -> bool:
        return cls.__get_login_credentials() is not None

    @staticmethod
    def __get_login_credentials() -> Optional[Tuple[str, str]]:
        username = os.getenv('ROUTER_USER')
        password = os.getenv('ROUTER_PASSWORD')
        if not username or not password:
            return None
        return username, password

    @classmethod
    def __create_new_connection(cls) -> Tuple[RouterOsApi, RouterOsApiPool]:
        username, password = cls.__get_login_credentials()
        conn = RouterOsApiPool(ROUTER_ADDRESS,
                               username=username,
                               password=password,
                               use_ssl=True,
                               ssl_verify=False,
                               plaintext_login=True)
        return conn.get_api(), conn

    @classmethod
    def watchdog(cls) -> None:
        while True:
            sleep(300)
            with cls.__cache_lock:
                old_sessions: Set[int] = set()
                for session_id, data in cls.__thread_cache.items():
                    if time() - data['last_heartbeat_check'] > 11 * 60:
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
        api, lock = cls.__get()
        with lock:
            return api.get_resource(path)


def rt(data: any) -> Response:
    return Response(json.dumps(data), mimetype='application/json')


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


def set_doh_enabled(enabled: bool, reset_after: Optional[int] = None) -> None:
    """
    Enables/disables DoH
    :param enabled: True if DoH should be enabled
    :param reset_after: if not None, then opposite state is set after given seconds
    :return: None
    """

    curr_is_enabled = API.call('/ip/dns').get()[0].get('use-doh-server', '') == DoH_SERVER

    if not curr_is_enabled and enabled:
        API.call('/ip/dns').call('set', arguments={
            'use-doh-server': DoH_SERVER,
            'verify-doh-cert': 'yes',
            'servers': '' if DNS_TRUSTED_SERVERS is None else DNS_TRUSTED_SERVERS
        })
    elif curr_is_enabled is not enabled:
        API.call('/ip/dns').call('set', arguments={
            'use-doh-server': '',
            'servers': '1.1.1.1,1.0.0.1,8.8.8.8,8.4.4.8' if DNS_FALLBACK_SERVERS is None else DNS_FALLBACK_SERVERS
        })

    if reset_after is not None:
        def reset() -> None:
            sleep(reset_after)
            set_doh_enabled(not enabled)

        Thread(target=reset, daemon=True).start()


def limit_get_names() -> Iterable[str]:
    r = map(lambda x: x['name'], API.call('/queue/simple').get())
    return r


def limit_remove(name: str) -> None:
    limits = API.call('/queue/simple')
    limit_id = limits.get(name=name)[0]['id']
    limits.remove(id=limit_id)


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
    API.call('/queue/simple').call('add', arguments={
        'name': name,
        'target': f"{target}/32" if target != "EVERYONE" else LOCAL_NETWORK,
        'max-limit': "%.2fM/%.2fM" % (upload * 8, download * 8)
    })


def limits_fetch() -> RequestLimits:
    r: RequestLimits = []
    for limit in API.call('/queue/simple').get():
        name: str = limit.get('name')
        if not name.startswith('_'):
            continue
        _, target, timeout = name.split('_')
        upload, download = limit.get('max-limit').split('/')
        timeout = int(timeout) if timeout != 'EVER' else None
        r.append((name, str(target), int(download) / 8000000, int(upload) / 8000000, timeout))
    return r


def log(*args) -> None:
    date = datetime.now().strftime("%Y/%m/%d %H:%M:%S")
    line = ' '.join([str(x) for x in args])
    line_offset = " " * (len(date) + 1)

    line = line.replace('\n', '\n' + line_offset)

    line = f"{date}: {line}"
    print(line, flush=True)
    SELF_LOG_QUEUE.put(line)


@retry_on_error
def get_updates_available() -> bool:
    res = API.call('/system/package/update').call('check-for-updates')
    return 'available' in res[-1]['status'].lower()


@retry_on_error
def get_log() -> List[Dict[str, str]]:
    res = API.call('/log').get()
    return res


@retry_on_error
def get_sniffer_running() -> bool:
    r = API.call('/tool/sniffer').get()[0]['running'] == 'true'
    return r


@retry_on_error
def get_arp_clients() -> Dict[str, str]:
    response_arp = API.call('/ip/arp').get()
    r: Dict[str, str] = {}
    for client in response_arp:
        if ARP_WATCH_INTERFACE is not None and client.get('interface') != ARP_WATCH_INTERFACE:
            continue
        if 'mac-address' not in client:
            continue
        if 'address' not in client:
            continue
        r[client['mac-address'].upper()] = client['address'].lower()
    return r


def remove_arp_client(mac: str) -> None:
    mac = mac.upper()

    client_removed = True

    while client_removed:
        for client in API.call('/ip/arp').get():
            if client.get('mac-address', '').upper() != mac:
                continue
            API.call('/ip/arp').remove(numbers=client['id'])
            break
        else:
            client_removed = False


@retry_on_error
def get_clients() -> CachedRequestActiveClientsCache:
    response_leases = API.call('/ip/dhcp-server/lease').get()
    arp_clients = get_arp_clients()
    r: CachedRequestActiveClientsCache = []
    for client in response_leases:
        if client.get('address', '') == ROUTER_ADDRESS:
            continue
        if client.get('disabled', 'false') == 'true':
            continue

        client_address: str = client.get('address', '').lower()
        client_name: Optional[str] = client.get('comment')
        client_saved_mac = client.get('mac-address', '').upper()
        client_active_mac: str = client.get('active-mac-address', '').upper()
        client_active: bool = (
                client.get('status', '') == 'bound'
                or client_active_mac in arp_clients
                or client_saved_mac in arp_clients
                )
        client_imposter = (
                client_name
                and client_active
                and client_saved_mac != client_active_mac
                and (client_saved_mac not in arp_clients or arp_clients[client_saved_mac] != client_address)
        )

        if client_imposter:
            client_name += ' (IMPOSTER)'

        r.append((
            client_address,
            client_name,
            client_active,
            client_active_mac,
            client_saved_mac
        ))

        if client_active_mac in arp_clients:
            del arp_clients[client_active_mac]
        if client_saved_mac in arp_clients:
            del arp_clients[client_saved_mac]

    for arp_mac, arp_ip in arp_clients.items():
        r.append((
            arp_ip,
            None,
            True,
            arp_mac,
            None
        ))

    return r


@retry_on_error
def get_net_usage_by_ip() -> CachedRequestNetUsageByIPCache:
    ip_speed: Dict[str, Tuple[int, int]] = {}
    if not get_sniffer_running():
        API.call('/tool/sniffer').call('start')
    packets = API.call('/tool/sniffer/host').get()
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


@auth.verify_password
def verify_password(username: str, password: str):
    if UI_USER is not None and username != UI_USER:
        return False
    if UI_PASSWORD is not None and password != UI_PASSWORD:
        return False
    return True


@app.route('/')
@auth.login_required
def web_root() -> str:
    return render_template('index.html', router_address=ROUTER_ADDRESS)


@app.route('/api/clients')
@auth.login_required
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


@app.route('/api/clients/all')
@auth.login_required
def api_clients_all() -> Response:
    r: CachedRequestActiveClientsCache = get_clients()
    if FILE_ARP_WATCH_DB is not None and os.path.isfile(FILE_ARP_WATCH_DB):
        with open(FILE_ARP_WATCH_DB, 'r') as f:
            ever_seen: Dict[str, str] = json.load(f)
        for mac in ever_seen.keys():
            for client in r:
                if client[3] == mac or client[4] == mac:
                    break
            else:
                r.append(('', None, False, '', mac))
    return rt(r)


@app.route('/api/net-usage-by-ip')
@auth.login_required
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


@app.route('/api/new-limit', methods=['POST'])
@auth.login_required
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

    return redirect(request.referrer if request.referrer else url_for('web_root'))


@app.route('/api/limit-remove', methods=['POST'])
@auth.login_required
def api_limit_remove() -> Response:
    name = request.form.get('name')
    assert name
    limit_remove(name)
    return redirect(request.referrer if request.referrer else url_for('web_root'))


@app.route('/api/limits')
@auth.login_required
def api_limits() -> Response:
    return rt(limits_fetch())


def send_notification(msg: str) -> bool:
    if notification_module is None:
        return False
    return notification_module.send_notification(msg)


@retry_on_error
def thread_stop_sniffer() -> None:
    while True:
        if CACHE['net-usage-by-ip'].nextRequestTime > 0 and \
                CACHE['net-usage-by-ip'].nextRequestTime - time() < -600 and get_sniffer_running():
            API.call('/tool/sniffer').call('stop')
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

            if FILE_ROUTER_LOG:
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
                log("[DNS]", "disabling DoH because of server failure")
                set_doh_enabled(False, 120)
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
    if not FILE_SELF_LOG:
        return
    while True:
        line = SELF_LOG_QUEUE.get()
        try:
            with FILE_SELF_LOG.open('a') as f:
                f.write(line + '\n')
        except PermissionError:
            print(f'[LOG] Fatal: Cannot access log file "{FILE_SELF_LOG}"')


@retry_on_error
def thread_monitor_dns() -> None:
    if DNS_MONITOR_DOMAINS_FILE is None:
        return
    file_bad_domains = Path(DNS_MONITOR_DOMAINS_FILE)

    filtered_bad_domains: Set[str] = set()
    with file_bad_domains.open('r') as f:
        filtered_bad_domains.update(
            filter(
                lambda x: not not x and not x.startswith('#'),
                map(lambda x: x.strip(), f.readlines())
            )
        )

    seen_bad_domains_last: Set[str] = set()

    while True:
        cache = API.call('/ip/dns/cache').get()
        seen_bad_domains_now: Set[str] = set()
        for record in cache:
            name: str = record['name']
            data: str = record['data']
            for bad_domain in filtered_bad_domains:
                if bad_domain in name or bad_domain in data:
                    seen_bad_domains_now.add(bad_domain)
                    if bad_domain in seen_bad_domains_last:
                        continue
                    message = f"[DNS MONITOR] Bad domain accessed '{name}' -> '{data}'"
                    log(message)
                    send_notification(message)
        seen_bad_domains_last = seen_bad_domains_now
        sleep(5 * 60 + randint(0, 280))


@retry_on_error
def thread_arp_watch() -> None:
    # mac: discovered_time
    arp_connected_clients: Dict[str, int] = {}

    known_mac_addresses: Set[str] = set()

    if FILE_ARP_WATCH_DB is not None and os.path.isfile(FILE_ARP_WATCH_DB):
        with open(FILE_ARP_WATCH_DB, 'r') as f:
            known_mac_addresses.update(map(lambda x: x.upper(), json.load(f)))

    while True:
        new_unknown_device = False
        for mac, ip in get_arp_clients().items():
            if mac in arp_connected_clients:
                continue
            arp_connected_clients[mac] = int(time())

            if FILE_ARP_WATCH_DB and mac not in known_mac_addresses:
                new_unknown_device = True
                log(f"[ARP WATCH] New device connected with MAC '{mac}' as '{ip}'")

        if ARP_AUTO_REMOVE_TIME is not None:
            removed_macs: Set[str] = set()
            for mac, connected_time in arp_connected_clients.items():
                if time() - connected_time < ARP_AUTO_REMOVE_TIME:
                    continue
                removed_macs.add(mac)
                remove_arp_client(mac)
            for mac in removed_macs:
                del arp_connected_clients[mac]

        if FILE_ARP_WATCH_DB is not None and new_unknown_device:
            with open(FILE_ARP_WATCH_DB, 'w') as f:
                json.dump(list(known_mac_addresses), f, indent=1)
        sleep(5 * 60 + randint(0, 280))


def main() -> int:
    log("[MAIN] starting up")
    if not API.is_ready():
        log("[MAIN] Error: Login credentials are missing!")
        return 1
    if not WEB_PORT or not LOCAL_NETWORK or not ROUTER_ADDRESS:
        log("[MAIN] Error: Some required settings are missing")
        return 1
    Thread(target=API.watchdog, daemon=True).start()
    Thread(target=thread_notif_logged_errors, daemon=True).start()
    Thread(target=thread_check_updates, daemon=True).start()
    Thread(target=thread_stop_sniffer, daemon=True).start()
    Thread(target=thread_check_cpu, daemon=True).start()
    Thread(target=thread_write_log, daemon=True).start()
    Thread(target=thread_remove_old_limits, daemon=True).start()
    Thread(target=thread_monitor_dns, daemon=True).start()
    if DoH_SERVER is not None:
        set_doh_enabled(True)
        Thread(target=thread_test_dns, daemon=True).start()
    if FILE_ARP_WATCH_DB is not None or ARP_AUTO_REMOVE_TIME is not None:
        Thread(target=thread_arp_watch, daemon=True).start()
    log(f"[MAIN] Starting web server @ http://127.0.0.1:{WEB_PORT}")
    http_server = WSGIServer(('127.0.0.1', int(WEB_PORT)), app)
    try:
        http_server.serve_forever()
    except KeyboardInterrupt:
        log("[MAIN] Shutting down")
    return 0


if __name__ == '__main__':
    exit(main())
