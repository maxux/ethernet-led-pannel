import asyncio
import websockets
import json
import binascii
from socket import *

srcmac = "b8:27:eb:51:1e:b3"
dstmac = "a2:43:42:42:42:01"
listen = "0.0.0.0"
wsport = 8765

def mactobin(macaddr):
    return binascii.unhexlify(macaddr.replace(":", ""))

def sendeth(destination, source, etype, payload, interface="eth0"):
    s = socket(AF_PACKET, SOCK_RAW)
    s.bind((interface, 0))

    print(source + destination + etype + payload)
    s.send(source + destination + etype + payload)

async def colorpick(websocket, path):
    while True:
        jcolor = await websocket.recv()
        color = json.loads(jcolor)

        print(color)

        bcolor = bytes([color['r'], color['g'], color['b']])
        sendeth(dstmac, srcmac, b"\x88\xb6", bcolor)

        await websocket.send(json.dumps({"status": "success"}))

start_server = websockets.serve(colorpick, listen, wsport)

print("[+] listening on ws://%s:%d" % (listen, wsport))
asyncio.get_event_loop().run_until_complete(start_server)
asyncio.get_event_loop().run_forever()

