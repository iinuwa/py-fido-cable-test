#!/home/isaiah/Development/python/cable-test/env/bin/python3

import asyncio
from bleak import BleakScanner

async def run():
    loop.get_running_loop
    devices = await BleakScanner.discover(
        service_uuids=[
            "0000fde2-0000-1000-8000-00805f9b34fb",
            "0000fff9-0000-1000-8000-00805f9b34fb",
        ],
        scanning_mode="active"
    )
    for d in devices:
        print(d.details)
        print(d)

# loop = asyncio.get_event_loop()
asyncio.run(run())
