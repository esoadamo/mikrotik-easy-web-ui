# Mikrotik Easy-Web UI

![WEB UI screenshot](https://user-images.githubusercontent.com/15877754/119484457-55d82d80-bd56-11eb-9a3e-692a0c95e7ce.png)

## Features

- shows active clients
- shows current download/upload usage per client
- can limit maximal usage for whole network/single device
- automatic DoH heartbeat check
- local copy of router log
- router error notifications
- high CPU usage notification
- available update notification

## Installation

### Account creation

1. create new user group (`api`) with following permissions: `reboot, read, write, policy, test, sniff, api`
2. create new user (`api`) and assign him to the created group

### Software installation

```bash
# 1. clone the repository
git clone https://github.com/esoadamo/mikrotik-easy-web-ui.git
cd mikrotik-easy-web-ui
# 2. (optional) create venv
python -m venv venv
# 3. install requirements
pip install -r requirements.txt
# 4. edit settings
cp .env.sample .env
nano .env
# 5. (optional) implement notification service
cp notification.sample.py notification.py  # and then edit function send_notification 
```

