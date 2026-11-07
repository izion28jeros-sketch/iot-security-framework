"""Emulated smart home testbed.
Starts five emulated IoT devices on loopback addresses 127.0.10.11-15 so the
assessment framework can be demonstrated without physical hardware.
Each device exposes the kind of services real consumer devices expose.
Run: python3 emulated_devices.py
"""
import asyncio, base64, json

CAM, PLUG, THERM, HUB, BULB = "127.0.10.11", "127.0.10.12", "127.0.10.13", "127.0.10.14", "127.0.10.15"

def http_response(status, body, ctype="text/html", extra=""):
    b = body.encode()
    return (f"HTTP/1.1 {status}\r\nServer: {{server}}\r\nContent-Type: {ctype}\r\n"
            f"Content-Length: {len(b)}\r\n{extra}Connection: close\r\n\r\n").encode() + b

def make_http(server, title, routes, basic_auth=None):
    async def handle(reader, writer):
        try:
            data = await asyncio.wait_for(reader.read(4096), 3)
            line = data.split(b"\r\n", 1)[0].decode(errors="ignore")
            path = line.split(" ")[1] if " " in line else "/"
            headers = data.decode(errors="ignore").lower()
            if basic_auth:
                good = "authorization: basic " + base64.b64encode(basic_auth.encode()).decode().lower()
                if good not in headers:
                    resp = http_response("401 Unauthorized", "<h1>401</h1>", extra='WWW-Authenticate: Basic realm="IPCam"\r\n')
                    writer.write(resp.replace(b"{server}", server.encode())); await writer.drain(); writer.close(); return
            body, ctype = routes.get(path, (f"<html><head><title>{title}</title></head><body><h1>{title}</h1></body></html>", "text/html"))
            writer.write(http_response("200 OK", body, ctype).replace(b"{server}", server.encode()))
            await writer.drain()
        except Exception:
            pass
        finally:
            writer.close()
    return handle

def make_banner(banner, replies=None):
    async def handle(reader, writer):
        try:
            writer.write(banner.encode()); await writer.drain()
            while replies:
                data = await asyncio.wait_for(reader.readline(), 5)
                if not data: break
                cmd = data.decode(errors="ignore").strip().split(" ")[0].upper()
                writer.write(replies.get(cmd, "500 Unknown command\r\n").encode()); await writer.drain()
                if cmd == "QUIT": break
        except Exception:
            pass
        finally:
            writer.close()
    return handle

async def rtsp(reader, writer):
    try:
        data = await asyncio.wait_for(reader.read(2048), 3)
        cseq = "1"
        for l in data.decode(errors="ignore").split("\r\n"):
            if l.lower().startswith("cseq"): cseq = l.split(":")[1].strip()
        writer.write(f"RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\nPublic: OPTIONS, DESCRIBE, SETUP, PLAY, TEARDOWN\r\nServer: Emulated IPCam RTSP\r\n\r\n".encode())
        await writer.drain()
    except Exception: pass
    finally: writer.close()

async def mqtt(reader, writer):
    try:
        data = await asyncio.wait_for(reader.read(1024), 3)
        if data and data[0] >> 4 == 1:          # CONNECT packet
            writer.write(bytes([0x20, 0x02, 0x00, 0x00]))  # CONNACK, accepted, no auth required
            await writer.drain()
    except Exception: pass
    finally: writer.close()

async def main():
    servers = [
        # 1. Smart IP camera: web UI with default admin/admin, open RTSP, Telnet
        (make_http("lighttpd/1.4.35", "Emulated IP Camera", {}, basic_auth="admin:admin"), CAM, 80),
        (rtsp, CAM, 554),
        (make_banner("\r\nBusyBox v1.24.1 (2016-03-04) built-in shell\r\nIPCam login: "), CAM, 23),
        # 2. Smart plug: unauthenticated JSON API over plain HTTP
        (make_http("SmartPlug-httpd/0.9", "Emulated Smart Plug", {
            "/": ('{"device":"Emulated Smart Plug","model":"SP-100","fw":"1.0.4","relay_state":1}', "application/json"),
            "/api/relay": ('{"relay_state":1,"auth":"none"}', "application/json")}), PLUG, 80),
        # 3. Thermostat: web UI on 8080 and MQTT broker without authentication
        (make_http("Mongoose/6.7", "Emulated Smart Thermostat", {}), THERM, 8080),
        (mqtt, THERM, 1883),
        # 4. Voice assistant hub: info endpoint leaking model and firmware
        (make_http("HubOS-web/2.1", "Emulated Voice Assistant Hub", {
            "/setup/eureka_info": ('{"name":"Emulated Voice Hub","build_version":"1.46.2","mac":"00:11:22:33:44:55","ssid":"Testbed-WiFi"}', "application/json")}), HUB, 8008),
        # 5. Smart bulb: FTP with anonymous login enabled
        (make_banner("220 Emulated SmartBulb FTP (vsFTPd 2.3.4)\r\n",
                     {"USER": "331 Please specify the password.\r\n", "PASS": "230 Login successful.\r\n", "QUIT": "221 Goodbye.\r\n"}), BULB, 21),
    ]
    started = []
    for handler, host, port in servers:
        started.append(await asyncio.start_server(handler, host, port))
        print(f"listening {host}:{port}", flush=True)
    await asyncio.gather(*(s.serve_forever() for s in started))

if __name__ == "__main__":
    asyncio.run(main())
