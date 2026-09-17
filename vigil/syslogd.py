"""Built-in syslog receiver: FortiGate -> UDP/TCP 514 (container port 5514) -> /data/logs/fortigate.log.

* UDP datagrams and TCP streams (newline framing, or RFC 6587 octet counting used by FortiOS "reliable" syslog).
* Each line is written as "<receive time UTC ISO> <sender ip> <message without the <PRI>>".
* Rotation when the file passes VIGIL_LOG_ROTATE_MB or the UTC day changes: fortigate.log -> .1, older files are
  gzipped (.2.gz ...) and only VIGIL_LOG_KEEP rotated files are kept. The ingest follows rotations exactly-once.
* VIGIL_SYSLOG_ALLOW = comma separated IPs/CIDRs allowed to send (default: anyone).
* Status (messages, rate, senders, last message) goes to /data/status/receiver.json for the Health page.
"""
import asyncio
import glob
import gzip
import ipaddress
import json
import logging
import os
import re
import shutil
import threading
import time
from datetime import datetime, timezone

from . import settings

PORT = int(os.environ.get('VIGIL_SYSLOG_PORT', '5514'))
ROTATE_BYTES = int(os.environ.get('VIGIL_LOG_ROTATE_MB', '512')) * 2**20
KEEP = int(os.environ.get('VIGIL_LOG_KEEP', '14'))
ALLOW = [ipaddress.ip_network(x.strip(), strict=False) for x in os.environ.get('VIGIL_SYSLOG_ALLOW', '').split(',') if x.strip()]
STATUS_PATH = os.path.join(settings.DATA, 'status', 'receiver.json')
PRI = re.compile(rb'^<\d{1,3}>(?:1 )?')
log = logging.getLogger('vigil.syslogd')


class Writer:
    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()
        self.fh = None
        self.day = None
        self.buf = []
        self.stats = {'messages': 0, 'bytes': 0, 'dropped_not_allowed': 0, 'senders': {}, 'last_ts': None,
                      'started': int(time.time() * 1000)}
        self._open()

    def _open(self):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        self.fh = open(self.path, 'ab', buffering=1 << 20)
        self.day = datetime.now(timezone.utc).date()

    def add(self, sender, msg):
        msg = PRI.sub(b'', msg.strip(b'\r\n\x00 '))
        if not msg:
            return
        now = datetime.now(timezone.utc)
        line = now.strftime('%Y-%m-%dT%H:%M:%S+00:00 ').encode() + sender.encode() + b' ' + msg.replace(b'\n', b' ') + b'\n'
        with self.lock:
            self.buf.append(line)
            s = self.stats
            s['messages'] += 1
            s['bytes'] += len(line)
            s['last_ts'] = int(now.timestamp() * 1000)
            snd = s['senders'].setdefault(sender, [0, 0])
            snd[0] += 1
            snd[1] = s['last_ts']

    def flush(self):
        with self.lock:
            buf, self.buf = self.buf, []
        if buf:
            self.fh.write(b''.join(buf))
            self.fh.flush()
        if self.fh.tell() >= ROTATE_BYTES or datetime.now(timezone.utc).date() != self.day:
            self.rotate()

    def rotate(self):
        self.fh.close()
        if os.path.exists(self.path) and os.path.getsize(self.path) > 0:
            base = self.path
            olds = sorted(glob.glob(base + '.*.gz'), key=lambda p: int(p.rsplit('.', 2)[1]), reverse=True)
            for p in olds:
                n = int(p.rsplit('.', 2)[1])
                if n + 1 > KEEP:
                    os.remove(p)
                else:
                    os.replace(p, f'{base}.{n + 1}.gz')
            if os.path.exists(base + '.1'):
                os.replace(base + '.1', base + '.2')           # rename first, compress in the background
                threading.Thread(target=_gzip, args=(base + '.2', base + '.2.gz'), daemon=True).start()
            os.replace(base, base + '.1')
        self._open()
        log.info('rotated %s', self.path)


def _gzip(src, dst):
    tmp = dst + '.tmp'
    try:
        with open(src, 'rb') as fi, gzip.open(tmp, 'wb', compresslevel=5) as fo:
            shutil.copyfileobj(fi, fo, 4 << 20)
        os.replace(tmp, dst)
        os.remove(src)
    except OSError as e:
        log.warning('gzip %s failed: %s', src, e)


def allowed(ip):
    if not ALLOW:
        return True
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in n for n in ALLOW)


class UDP(asyncio.DatagramProtocol):
    def __init__(self, w):
        self.w = w

    def datagram_received(self, data, addr):
        if not allowed(addr[0]):
            self.w.stats['dropped_not_allowed'] += 1
            return
        for part in data.split(b'\n'):
            self.w.add(addr[0], part)


async def tcp_client(w, reader, writer):
    peer = writer.get_extra_info('peername')[0]
    if not allowed(peer):
        w.stats['dropped_not_allowed'] += 1
        writer.close()
        return
    buf = b''
    try:
        while True:
            chunk = await reader.read(65536)
            if not chunk:
                break
            buf += chunk
            while buf:
                m = re.match(rb'^(\d{1,6}) ', buf)
                if m:                                              # octet counting: "<len> <msg>"
                    n, start = int(m.group(1)), m.end()
                    if len(buf) < start + n:
                        break
                    w.add(peer, buf[start:start + n])
                    buf = buf[start + n:]
                    continue
                i = buf.find(b'\n')
                if i < 0:
                    if len(buf) > 1 << 20:                         # no framing at all: do not grow forever
                        w.add(peer, buf)
                        buf = b''
                    break
                w.add(peer, buf[:i])
                buf = buf[i + 1:]
    except (ConnectionError, asyncio.IncompleteReadError):
        pass
    finally:
        writer.close()


def write_status(w, rate):
    s = dict(w.stats, rate_per_s=rate, port=PORT, allow=[str(n) for n in ALLOW] or ['any'], file=w.path)
    s['senders'] = [{'ip': ip, 'messages': v[0], 'last_ts': v[1]} for ip, v in sorted(w.stats['senders'].items(), key=lambda x: -x[1][0])[:20]]
    os.makedirs(os.path.dirname(STATUS_PATH), exist_ok=True)
    tmp = STATUS_PATH + '.tmp'
    with open(tmp, 'w') as f:
        json.dump(s, f)
    os.replace(tmp, STATUS_PATH)


async def main():
    settings.ensure_dirs()
    w = Writer(settings.LOG_BASE)
    loop = asyncio.get_running_loop()
    await loop.create_datagram_endpoint(lambda: UDP(w), local_addr=('0.0.0.0', PORT))
    server = await asyncio.start_server(lambda r, wr: tcp_client(w, r, wr), '0.0.0.0', PORT)
    log.info('listening on udp/tcp %d, writing %s (allowed senders: %s)', PORT, w.path, ', '.join(map(str, ALLOW)) or 'any')
    last_n, last_t = 0, time.time()
    async with server:
        while True:
            await asyncio.sleep(0.5)
            w.flush()
            if time.time() - last_t >= 5:
                rate = round((w.stats['messages'] - last_n) / (time.time() - last_t), 1)
                last_n, last_t = w.stats['messages'], time.time()
                write_status(w, rate)


def run():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(name)s %(message)s')
    asyncio.run(main())


if __name__ == '__main__':
    run()
