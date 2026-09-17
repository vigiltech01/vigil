"""Response cache + background warmer so the preset ranges (24h / 7d / 30d) always load instantly.

A cached value is served while it is younger than its TTL. When it is older, one caller recomputes it while
everybody else keeps getting the previous value (stale-while-revalidate). The warmer thread recomputes the preset
ranges of the heavy endpoints before they expire.
"""
import logging
import os
import threading
import time

log = logging.getLogger('vigil.cache')

PRESETS = {'15m': (15 * 60_000, 30), '1h': (3_600_000, 30), '6h': (6 * 3_600_000, 60),
           '24h': (86_400_000, 180), '7d': (7 * 86_400_000, 900), '30d': (30 * 86_400_000, 2700)}
WARM = ('24h', '7d', '30d')


MAX_ENTRIES = 80                                    # custom-range entries beyond this are evicted oldest-first
MAX_AGE_S = 3600                                    # and none is kept longer than an hour (presets are re-warmed)


class Cache:
    def __init__(self):
        self.data = {}
        self.locks = {}
        self.glock = threading.Lock()

    def prune(self, keep_presets=True):
        now = time.time()
        with self.glock:
            preset = {k for k in self.data if keep_presets and len(k) == 2 and k[1] in PRESETS}
            for k in [k for k, (t, _) in list(self.data.items()) if k not in preset and now - t > MAX_AGE_S]:
                self.data.pop(k, None)
            others = sorted((t, k) for k, (t, _) in list(self.data.items()) if k not in preset)
            for _, k in others[:max(0, len(others) - MAX_ENTRIES)]:
                self.data.pop(k, None)
            for k in [k for k, lk in self.locks.items() if k not in self.data and not lk.locked()]:
                self.locks.pop(k, None)

    def get(self, key, fn, ttl):
        ent = self.data.get(key)
        if ent and time.time() - ent[0] < ttl:
            return ent
        with self.glock:
            lock = self.locks.setdefault(key, threading.Lock())
        if ent and not lock.acquire(blocking=False):
            return ent                                  # someone is refreshing: serve the previous result
        if not ent:
            lock.acquire()
        try:
            cur = self.data.get(key)
            if cur and cur is not ent and time.time() - cur[0] < ttl:
                return cur
            val = fn()
            ent = self.data[key] = (time.time(), val)
            if len(self.data) > MAX_ENTRIES:
                self.prune()
            return ent
        finally:
            lock.release()


cache = Cache()
_endpoints = {}


def register(name, fn):
    """fn(frm, to) -> JSON-able; warmed for the WARM presets."""
    _endpoints[name] = fn


def cached(name, fn, preset, frm, to):
    """Return (generated_epoch_s, value). Presets are now-relative and shared; custom ranges are keyed by minute."""
    if preset in PRESETS:
        span, ttl = PRESETS[preset]

        def compute():
            now = int(time.time() * 1000)
            return fn(now - span, now)
        return cache.get((name, preset), compute, ttl)
    return cache.get((name, frm // 60_000, to // 60_000), lambda: fn(frm, to), 300)


def _warm_loop():
    try:
        os.setpriority(os.PRIO_PROCESS, threading.get_native_id(), 10)   # Linux: nice only this thread
    except (OSError, AttributeError):
        pass
    time.sleep(20)
    while True:
        cache.prune()
        for preset in WARM:
            span, ttl = PRESETS[preset]
            for name, fn in list(_endpoints.items()):
                ent = cache.data.get((name, preset))
                if ent and time.time() - ent[0] < ttl * 0.75:
                    continue
                t0 = time.time()
                try:
                    now = int(time.time() * 1000)
                    val = fn(now - span, now)
                    cache.data[(name, preset)] = (time.time(), val)
                    log.info('warmed %s %s in %.1fs', name, preset, time.time() - t0)
                except Exception as e:                  # keep warming the others
                    log.warning('warm %s %s failed: %s', name, preset, e)
                time.sleep(2)
        time.sleep(10)


def start_warmer():
    t = threading.Thread(target=_warm_loop, name='cache-warmer', daemon=True)
    t.start()
    return t
