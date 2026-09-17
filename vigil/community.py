"""Community features: the optional contact form endpoint and the anonymous daily usage ping.

The ping tells the Vigil team how many installs exist and roughly how they are used. It is sent once a day to
COMMUNITY_URL and contains ONLY the fields built in `ping_payload()` - a random install ID, the version, CPU
architecture, whether demo mode / a configuration backup / login are on, days since install, how many firewalls send
logs and a coarse log-rate bucket. Never log lines, IP addresses, hostnames, firewall names, rules or credentials.

Turn it off with VIGIL_TELEMETRY=off, or in Settings -> Community (stored in settings.json as "telemetry").
"""
import json
import logging
import os
import platform
import random
import time
import urllib.request
import uuid

from . import __version__, settings

log = logging.getLogger('vigil.community')

# Google Apps Script web app run by the Vigil team (receives contact requests and usage pings)
DEFAULT_URL = ''
COMMUNITY_URL = os.environ.get('VIGIL_COMMUNITY_URL', DEFAULT_URL).strip()
ENV_OFF = os.environ.get('VIGIL_TELEMETRY', 'on').strip().lower() in ('off', '0', 'false', 'no', 'disabled')
INSTANCE_PATH = os.path.join(settings.DATA, 'instance.json')
STATUS_PATH = os.path.join(settings.DATA, 'status', 'telemetry.json')
INTERVAL_S = 86_400


def instance():
    """Random install ID created on first use (not derived from anything on the machine)."""
    try:
        with open(INSTANCE_PATH) as f:
            d = json.load(f)
        if d.get('id') and d.get('created'):
            return d
    except (OSError, ValueError):
        pass
    d = {'id': str(uuid.uuid4()), 'created': int(time.time())}
    os.makedirs(os.path.dirname(INSTANCE_PATH), exist_ok=True)
    tmp = INSTANCE_PATH + '.tmp'
    with open(tmp, 'w') as f:
        json.dump(d, f)
    os.replace(tmp, INSTANCE_PATH)
    return d


def telemetry_enabled():
    return bool(COMMUNITY_URL) and not ENV_OFF and bool(settings.load().get('telemetry', True))


def _eps_bucket(rate):
    if rate is None:
        return 'unknown'
    for limit, label in ((0.01, '0'), (1, '<1'), (10, '1-10'), (100, '10-100'), (1000, '100-1000')):
        if rate < limit:
            return label
    return '1000+'


def _status(name):
    try:
        with open(os.path.join(settings.DATA, 'status', name)) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def ping_payload():
    """Exactly what is sent - also shown in Settings so people can see it."""
    inst = instance()
    receiver = _status('receiver.json')
    senders = receiver.get('senders') or {}
    from . import auth
    return {
        'type': 'ping',
        'instance_id': inst['id'],
        'version': __version__,
        'arch': platform.machine() or 'unknown',
        'demo': settings.DEMO,
        'days_installed': int((time.time() - inst['created']) // 86_400),
        'firewalls': len(senders) if isinstance(senders, (dict, list)) else 0,
        'eps_bucket': _eps_bucket(receiver.get('rate_per_s')),
        'config_loaded': os.path.exists(settings.CONFIG_PATH),
        'login_enabled': not auth.DISABLED,
    }


def status():
    try:
        with open(STATUS_PATH) as f:
            last = json.load(f)
    except (OSError, ValueError):
        last = {}
    return {'available': bool(COMMUNITY_URL), 'enabled': telemetry_enabled(), 'env_off': ENV_OFF,
            'setting': bool(settings.load().get('telemetry', True)), 'last_sent': last.get('sent'), 'last_ok': last.get('ok'),
            'preview': ping_payload()}


def send_ping():
    body = json.dumps(ping_payload()).encode()
    req = urllib.request.Request(COMMUNITY_URL, data=body, headers={'Content-Type': 'text/plain;charset=utf-8',
                                                                     'User-Agent': f'vigil/{__version__}'})
    ok = False
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            ok = 200 <= r.status < 400
    except Exception as e:                                # offline networks are normal - never fail loudly
        log.info('usage ping not delivered (%s)', type(e).__name__)
    os.makedirs(os.path.dirname(STATUS_PATH), exist_ok=True)
    with open(STATUS_PATH + '.tmp', 'w') as f:
        json.dump({'sent': int(time.time() * 1000), 'ok': ok}, f)
    os.replace(STATUS_PATH + '.tmp', STATUS_PATH)
    return ok


def run():
    """Supervisor component: first ping a few minutes after start, then once a day."""
    time.sleep(float(os.environ.get('VIGIL_TELEMETRY_FIRST_DELAY', '0')) or random.uniform(120, 600))
    while True:
        if telemetry_enabled():
            send_ping()
        time.sleep(INTERVAL_S + random.uniform(-1800, 1800))
