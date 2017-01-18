import asyncio

loop = asyncio.get_event_loop()
client_connected = lambda: 'client connected'

async def socks5_proxy(reader, writer):
    def connection_refuse():
        writer.write(b'\x05')
        await writer.drain()
        writer.close()
    ver = await reader.readexactly(1)
    if ver != b'\x05':
        connection_refuse()
        return
    nmeth = await reader.readexactly(1)
    if ord(nmeth) not in range(1, 256):
        connection_refuse()
        return
    meths = await reader.readexactly(ord(nmeth))
    if len(set(meths)) != len(meths):
        connection_refuse()
        return
    for meth in meths:
        if ord(meth) not in range(1, 256):
            connection_refuse()
            return
    # we could set others prefer in future,
    # no auth for now.
    if b'\x00' in meths:
        auth_meth = b'\x00'
    else:
        auth_meth = b'\xff' # no acceptable methods
    selection_msg = b'\x05' + auth_meth
    writer.write(selection_msg)
    await writer.drain()


server = loop.run_until_complete(asyncio.start_server(socks5_proxy, host='127.0.0.1', port=9377))
server.close()
loop.stop()
loop.close()
