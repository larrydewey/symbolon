#!/usr/bin/env python3
"""A TCP proxy that adds a fixed delay each way and counts connections, to
see what a vault operation costs over a slow link (a VPN):

    latency_proxy.py LISTEN_PORT TARGET_PORT DELAY_FILE COUNT_FILE

DELAY_FILE holds the one-way delay in milliseconds, read at each new
connection, so one setup can be timed at several delays.
"""
import asyncio, sys

listen, target, delay_file = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
count_file = sys.argv[4]
n = 0

def delay_now():
    try:
        return int(open(delay_file).read().strip()) / 1000
    except Exception:
        return 0

async def pipe(r, w, delay):
    try:
        while True:
            b = await r.read(65536)
            if not b:
                break
            await asyncio.sleep(delay)
            w.write(b)
            await w.drain()
    except Exception:
        pass
    finally:
        try:
            w.close()
        except Exception:
            pass

async def handle(cr, cw):
    global n
    n += 1
    delay = delay_now()
    open(count_file, 'w').write(str(n))
    await asyncio.sleep(delay)          # the SYN's way there
    try:
        sr, sw = await asyncio.open_connection('127.0.0.1', target)
    except Exception:
        cw.close()
        return
    await asyncio.sleep(delay)          # and back
    await asyncio.gather(pipe(cr, sw, delay), pipe(sr, cw, delay))

async def main():
    srv = await asyncio.start_server(handle, '127.0.0.1', listen)
    print('ready', flush=True)
    async with srv:
        await srv.serve_forever()

asyncio.run(main())
