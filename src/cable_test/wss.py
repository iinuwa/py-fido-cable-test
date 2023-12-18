import websockets
FIDO_CABLE_WSS_SUBPROTOCOL = "fido.cable"

async def connect(domain, routing_id, tunnel_id):
    routing_id_encoded = "".join([f"{x:02x}" for x in routing_id])
    tunnel_id_encoded = "".join([f"{x:02x}" for x in tunnel_id])

    url = f"wss://{domain}/cable/connect/{routing_id_encoded}/{tunnel_id_encoded}"

    async with websockets.client.connect(
        url,
        subprotocols=[FIDO_CABLE_WSS_SUBPROTOCOL]) as ws:
        if ws.subprotocol != FIDO_CABLE_WSS_SUBPROTOCOL:
            raise("Tunnel service picked the wrong protocol")
        do_handshake(ws, )