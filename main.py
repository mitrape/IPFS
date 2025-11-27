
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs
import socket
import struct
import json

ENGINE_SOCK = "/tmp/cengine.sock"

OP_UPLOAD_START = 0x01
OP_UPLOAD_CHUNK = 0x02
OP_UPLOAD_FINISH = 0x03
OP_UPLOAD_DONE  = 0x81

OP_DOWNLOAD_START = 0x11
OP_DOWNLOAD_CHUNK = 0x91
OP_DOWNLOAD_DONE  = 0x92

def frame(op, payload: bytes):
    return struct.pack(">BI", op, len(payload)) + payload

def engine_call(messages):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(ENGINE_SOCK)
    try:
        for m in messages:
            s.sendall(m)
        def recv_exact(n):
            buf = bytearray()
            while len(buf) < n:
                chunk = s.recv(n - len(buf))
                if not chunk:
                    raise ConnectionError("engine closed")
                buf.extend(chunk)
            return bytes(buf)
        while True:
            header = recv_exact(5)
            op, length = struct.unpack(">BI", header)
            data = recv_exact(length) if length else b""
            yield op, data
            if op in (OP_UPLOAD_DONE, OP_DOWNLOAD_DONE):
                break
    finally:
        s.close()

class Handler(BaseHTTPRequestHandler):
    server_version = "OS-Gateway/0.1"

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path != "/upload":
            self.send_error(404, "Not Found")
            return

        fname = self.headers.get("X-Filename")
        clen = self.headers.get("Content-Length")
        if not fname or not clen:
            self.send_error(400, "Missing X-Filename or Content-Length")
            return

        try:
            total = int(clen)
        except:
            self.send_error(400, "Invalid Content-Length")
            return

        msgs = [frame(OP_UPLOAD_START, fname.encode("utf-8"))]

        remaining = total
        CHUNK = 256 * 1024
        while remaining > 0:
            n = min(remaining, CHUNK)
            data = self.rfile.read(n)
            if not data or len(data) != n:
                self.send_error(400, "Body shorter than Content-Length")
                return
            msgs.append(frame(OP_UPLOAD_CHUNK, data))
            remaining -= n

        msgs.append(frame(OP_UPLOAD_FINISH, b""))

        cid = None
        for op, payload in engine_call(msgs):
            if op == OP_UPLOAD_DONE:
                cid = payload.decode("utf-8")

        if cid is None:
            self.send_error(502, "Engine did not return CID")
            return

        body = json.dumps({"cid": cid}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path != "/download":
            self.send_error(404, "Not Found")
            return
        q = parse_qs(parsed.query)
        cid = q.get("cid", [None])[0]
        if not cid:
            self.send_error(400, "Missing cid parameter")
            return

        msgs = [frame(OP_DOWNLOAD_START, cid.encode("utf-8"))]

        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.end_headers()

        for op, payload in engine_call(msgs):
            if op == OP_DOWNLOAD_CHUNK and payload:
                self.wfile.write(payload)
                self.wfile.flush()
            # OP_DOWNLOAD_DONE ends the stream

def run(host="127.0.0.1", port=9000):
    srv = ThreadingHTTPServer((host, port), Handler)
    print(f"HTTP gateway listening on http://{host}:{port}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()

if __name__ == "__main__":
    run()
