"""Transparent trusted same-origin HTTP/WSS facade for exclusive native tests."""
import http.client
import json
import select
import socket
import socketserver
import ssl
import threading
import time

class NativeTLSProxy:
    def __init__(self, port, http_port, ws_port, cert, key, observation):
        self.http_port, self.ws_port, self.observation = http_port, ws_port, observation
        self.lock = threading.Lock()
        self.rest_release = threading.Event()
        self.rest_release.set()
        self.rest_failures = 0
        self.reconnect_release = threading.Event()
        self.reconnect_release.set()
        self.hold_machine_id = None
        self.tunnels = {}
        self.tunnel_sequence = 0
        self.events = []
        owner = self
        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                client = self.request
                client.settimeout(15)
                raw = b''
                while b'\r\n\r\n' not in raw:
                    chunk = client.recv(4096)
                    if not chunk or len(raw) > 65536: return
                    raw += chunk
                header, rest = raw.split(b'\r\n\r\n', 1)
                lines = header.decode('iso-8859-1').split('\r\n')
                method, path, _ = lines[0].split(' ', 2)
                headers = dict(line.split(':', 1) for line in lines[1:] if ':' in line)
                headers = {k.strip(): v.strip() for k, v in headers.items()}
                lower = {k.lower(): v for k, v in headers.items()}
                upgrade = lower.get('upgrade', '').lower() == 'websocket'
                if upgrade:
                    if path != '/txapi/node/v1/ws': return
                    if (lower.get('x-tx-machine-id') == owner.hold_machine_id
                            and lower.get('user-agent') != 'TXNode-live-successor'):
                        owner.record({'kind':'reconnect-held','machine_id':lower.get('x-tx-machine-id')})
                        if not owner.reconnect_release.wait(timeout=10): return
                    with socket.create_connection(('127.0.0.1', owner.ws_port), timeout=5) as upstream:
                        upstream.sendall(header+b'\r\n\r\n'+rest)
                        response = b''
                        while b'\r\n\r\n' not in response:
                            part = upstream.recv(4096)
                            if not part:
                                # Workerman invokes authorization before sending
                                # its101 handshake. A rejected upgrade can close
                                # with no HTTP/WS response, so preserve that actual
                                # pre-upgrade refusal rather than inventing a frame.
                                owner.record({'kind':'ws-preupgrade-close','machine_id':lower.get('x-tx-machine-id'),'node_id':lower.get('x-tx-node-id'),'response_bytes':len(response)})
                                if response: client.sendall(response)
                                return
                            if len(response)>65536:return
                            response += part
                        status = int(response.split(b' ', 2)[1])
                        owner.record({'kind':'ws-upgrade','status':status,'machine_id':lower.get('x-tx-machine-id'),'node_id':lower.get('x-tx-node-id')})
                        client.sendall(response)
                        if status != 101: return
                        client.settimeout(None); upstream.settimeout(None)
                        with owner.lock:
                            owner.tunnel_sequence += 1
                            tunnel_id = owner.tunnel_sequence
                            owner.tunnels[tunnel_id] = (client, upstream, lower.get('x-tx-machine-id'))
                        # Forward original WebSocket bytes untouched. No fixture frames.
                        try:
                            while True:
                                ready,_,_ = select.select([client,upstream],[],[],1)
                                for source in ready:
                                    target = upstream if source is client else client
                                    data = source.recv(65536)
                                    if not data:return
                                    target.sendall(data)
                        except (OSError, ssl.SSLError): pass
                        finally:
                            with owner.lock: owner.tunnels.pop(tunnel_id, None)
                            owner.record({'kind':'ws-close','machine_id':lower.get('x-tx-machine-id')})
                    return
                if path in {'/txapi/node/v1/config', '/txapi/node/v1/users'}:
                    if not owner.rest_release.is_set():
                        owner.record({'kind':'rest-held','path':path,'node_id':lower.get('x-tx-node-id')})
                        if not owner.rest_release.wait(timeout=20): return
                    with owner.lock:
                        failed = owner.rest_failures > 0
                        if failed: owner.rest_failures -= 1
                    if failed:
                        payload=b'{"error":{"code":"FIXTURE_GATEWAY_TEMPORARY","message":"Temporary test gateway fault"},"request_id":"machine-gateway-fault"}'
                        owner.record({'kind':'gateway503','path':path,'node_id':lower.get('x-tx-node-id'),'status':503})
                        client.sendall(b'HTTP/1.1 503 Service Unavailable\r\nContent-Type: application/json\r\nConnection: close\r\n'+f'Content-Length: {len(payload)}\r\n\r\n'.encode()+payload)
                        return
                length = int(lower.get('content-length','0'))
                if length<0 or length>4<<20:return
                body = rest
                while len(body)<length:
                    part=client.recv(min(65536,length-len(body)))
                    if not part:return
                    body+=part
                headers.pop('Connection',None);headers['Connection']='close'
                upstream=http.client.HTTPConnection('127.0.0.1',owner.http_port,timeout=10)
                try:
                    upstream.request(method,path,body[:length] if length else None,headers)
                    response=upstream.getresponse();content=response.read(4<<20)
                    event={'kind':'http','method':method,'path':path.split('?',1)[0],'status':response.status,'node_id':lower.get('x-tx-node-id'),'machine_id':lower.get('x-tx-machine-id')}
                    if path=='/txapi/node/v1/report':
                        try:
                            payload=json.loads(body[:length]);event['batch_id']=payload.get('traffic_batch_id');event['traffic']=payload.get('traffic',{})
                        except (ValueError,TypeError): pass
                    if response.status>=400:
                        try:event['error_code']=json.loads(content).get('error',{}).get('code')
                        except (ValueError,TypeError): pass
                    owner.record(event)
                    output=f'HTTP/1.1 {response.status} {response.reason}\r\n'.encode()
                    output+=b''.join(f'{k}: {v}\r\n'.encode('iso-8859-1') for k,v in response.getheaders() if k.lower() not in {'connection','transfer-encoding','content-length'})
                    client.sendall(output+f'Content-Length: {len(content)}\r\nConnection: close\r\n\r\n'.encode()+content)
                finally:upstream.close()
        class Server(socketserver.ThreadingTCPServer):
            allow_reuse_address=True
            daemon_threads=True
        self.server=Server(('127.0.0.1',port),Handler)
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(cert,key)
        self.server.socket=context.wrap_socket(self.server.socket,server_side=True)
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True)
    def record(self,event):
        event['monotonic_ns']=time.monotonic_ns()
        with self.lock:
            self.events.append(event)
            with open(self.observation,'a',encoding='utf-8') as stream:
                stream.write(json.dumps(event,sort_keys=True)+'\n');stream.flush()
    def start(self):self.thread.start()
    def event_snapshot(self):
        with self.lock:return [dict(event) for event in self.events]
    def hold_rest(self):self.rest_release.clear()
    def release_rest(self):self.rest_release.set()
    def fail_rest(self, count):
        with self.lock:self.rest_failures=count
    def hold_reconnect(self, machine_id):
        self.hold_machine_id=str(machine_id)
        self.reconnect_release.clear()
    def release_reconnect(self):
        self.reconnect_release.set()
        self.hold_machine_id=None
    def disconnect_machine(self, machine_id):
        with self.lock:targets=[pair for pair in self.tunnels.values() if pair[2]==str(machine_id)]
        for client, upstream, _ in targets:
            for connection in (client, upstream):
                try:connection.shutdown(socket.SHUT_RDWR)
                except OSError:pass
        return len(targets)
    def close(self):
        self.release_rest()
        self.release_reconnect()
        with self.lock:targets=list(self.tunnels.values())
        for client,upstream,_ in targets:
            for connection in (client,upstream):
                try:connection.shutdown(socket.SHUT_RDWR)
                except OSError:pass
        self.server.shutdown();self.server.server_close();self.thread.join(timeout=2)
