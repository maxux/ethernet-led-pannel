import asyncio
import websockets
import json
from socket import *

def sendeth(source, destination, etype, payload, interface="bond0"):
    s = socket(AF_PACKET, SOCK_RAW)
    s.bind((interface, 0))

    s.send(source + destination + etype + payload)

async def colorpick(websocket, path):
    while True:
        jcolor = await websocket.recv()
        color = json.loads(jcolor)

        print(color)

        bcolor = bytes([color['r'], color['g'], color['b']])
        sendeth(b"\xa2\x43\x42\x42\x42\x01", b"\x28\xf1\x0e\x01\x6b\x84", b"\x88\xb6", bcolor)

        await websocket.send(json.dumps({"status": "success"}))

start_server = websockets.serve(colorpick, '0.0.0.0', 8765)

asyncio.get_event_loop().run_until_complete(start_server)
asyncio.get_event_loop().run_forever()

