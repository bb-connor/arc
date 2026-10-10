import http.client, json, sys, time
HOST, PORT = "127.0.0.1", int(sys.argv[1])
roots = sys.argv[2] == "roots"
H = {"content-type": "application/json", "accept": "application/json, text/event-stream", "authorization": "Bearer spike-edge-token"}
def post(body, extra=None, read=True, timeout=8):
    c = http.client.HTTPConnection(HOST, PORT, timeout=timeout)
    c.request("POST", "/mcp", body=json.dumps(body), headers={**H, **(extra or {})})
    r = c.getresponse()
    data = r.read() if read else b"(not read)"
    sid = r.getheader("mcp-session-id")
    c.close()
    return r.status, sid, data[:200]
caps = {"roots": {"listChanged": True}} if roots else {}
st, sid, data = post({"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":caps,"clientInfo":{"name":"probe","version":"0"}}})
print("initialize", st)
v = {"mcp-session-id": sid, "mcp-protocol-version": "2025-11-25"}
st, _, data = post({"jsonrpc":"2.0","method":"notifications/initialized"}, v, read=False)
print("initialized", st, data)
t = time.time()
try:
    st, _, data = post({"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}, v, timeout=6)
    print("tools/list", st, round(time.time()-t, 2), "s", data[:160])
except Exception as e:
    print("tools/list FAILED", type(e).__name__, round(time.time()-t, 2), "s")
