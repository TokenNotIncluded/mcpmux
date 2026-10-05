#!/usr/bin/env python3
"""Black-box transport and authorization checks; stdlib only, no secrets printed."""
import base64
import hashlib
import http.server
import json
import pathlib
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None

opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

def request(base, path, data=None, token=None, headers=None, method=None, form=False):
    h = dict(headers or {})
    if token:
        h['Authorization'] = 'Bearer ' + token
    if data is not None:
        if form:
            data = urllib.parse.urlencode(data).encode()
            h['Content-Type'] = 'application/x-www-form-urlencoded'
        elif not isinstance(data, bytes):
            data = json.dumps(data).encode()
            h['Content-Type'] = 'application/json'
            h.setdefault('Accept', 'application/json, text/event-stream')
    req = urllib.request.Request(base + path, data=data, headers=h, method=method)
    try:
        r = opener.open(req, timeout=5)
    except urllib.error.HTTPError as e:
        r = e
    with r:
        return r.status, r.headers, r.read().decode()

def rpc(text):
    if text.startswith('event:') or text.startswith('data:'):
        return json.loads(next(line[5:].strip() for line in text.splitlines() if line.startswith('data:')))
    return json.loads(text)

def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]

seen = []
class Upstream(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass
    def do_POST(self):
        seen.append({k.lower():v for k,v in self.headers.items()})
        body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        self.send_response(200)
        modern = self.headers.get('MCP-Protocol-Version') == '2026-07-28'
        self.send_header('Content-Type', 'text/event-stream' if modern else 'application/json')
        self.send_header('Mcp-Session-Id', 'private-upstream-session')
        self.end_headers()
        result = {'jsonrpc':'2.0','id':body['id'],'result':{'ok':True}}
        if modern:
            self.wfile.write(b'event: message\ndata: {"jsonrpc":"2.0","method":"notifications/progress","params":{"progress":1}}\n\n')
            self.wfile.flush()
            time.sleep(.05)
            self.wfile.write(('event: message\ndata: '+json.dumps(result)+'\n\n').encode())
        else:
            self.wfile.write(json.dumps(result).encode())
    def do_DELETE(self):
        seen.append({k.lower():v for k,v in self.headers.items()})
        self.send_response(204)
        self.end_headers()

binary = str(pathlib.Path(sys.argv[1]).resolve())
up = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Upstream)
threading.Thread(target=up.serve_forever, daemon=True).start()
with tempfile.TemporaryDirectory(prefix='mcpmux-e2e-') as tmp:
    d = pathlib.Path(tmp)
    subprocess.run([binary, 'bootstrap', tmp, 'https://mcp.example'], check=True, stdout=subprocess.DEVNULL)
    port = free_port()
    config = (d / 'mcpmux.toml').read_text().replace('127.0.0.1:8088', f'127.0.0.1:{port}')
    config = config.replace('[routes.demo]\n', '[routes.demo]\npath = "/jev"\n')
    static = (d / 'demo-token').read_text()
    password = (d / 'owner-password').read_text()
    remote_token = 'test-only-upstream-credential'
    (d / 'remote-token').write_text(remote_token)
    alias_token = 'test-only-alias-access-token'
    remote_access = 'test-only-http-access-token'
    weak_scope = 'test-only-insufficient-scope'
    ask_token = 'test-only-ask-token'
    config += f'''\n[upstreams.ask]
type = "stdio"
command = {json.dumps(sys.executable)}
args = [{json.dumps(str(pathlib.Path(__file__).with_name('fixture_stdio.py').resolve()))}]
[routes.ask]
upstream = "ask"
[tokens.ask]
sha256 = "{hashlib.sha256(ask_token.encode()).hexdigest()}"
subject = "owner"
route = "ask"
[upstreams.remote]
type = "http"
url = "http://127.0.0.1:{up.server_port}/mcp"
bearer_file = {json.dumps(str(d / 'remote-token'))}
[routes.remote]
upstream = "remote"
[tokens.remote]
sha256 = "{hashlib.sha256(remote_access.encode()).hexdigest()}"
subject = "owner"
route = "remote"
[tokens.alias]
sha256 = "{hashlib.sha256(alias_token.encode()).hexdigest()}"
subject = "owner"
route = "demo-alias"
[tokens.weak]
sha256 = "{hashlib.sha256(weak_scope.encode()).hexdigest()}"
subject = "owner"
route = "demo"
scopes = []
'''
    (d / 'mcpmux.toml').write_text(config)
    subprocess.run([binary, 'check', str(d / 'mcpmux.toml')], check=True, stdout=subprocess.DEVNULL)
    for invalid in ['/jev', '/token', '/bad//path', '/bad?query']:
        (d / 'invalid.toml').write_text(config.replace('[routes.remote]\n', '[routes.remote]\npath = '+json.dumps(invalid)+'\n'))
        assert subprocess.run([binary, 'check', str(d / 'invalid.toml')], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode != 0

    proc = subprocess.Popen([binary, 'serve', str(d / 'mcpmux.toml')], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    base = f'http://127.0.0.1:{port}'
    try:
        for _ in range(100):
            try:
                if request(base, '/healthz')[0] == 200:
                    break
            except OSError:
                time.sleep(.05)
        else:
            raise AssertionError('server did not start')
        code, h, _ = request(base, '/jev')
        assert code == 401 and 'resource_metadata=' in h['WWW-Authenticate']
        assert request(base, '/jev', token='bad')[0] == 401
        assert request(base, '/mcp/demo-alias', token=static)[0] == 401
        assert request(base, '/jev', token=weak_scope)[0] == 403
        assert request(base, '/jev', token=static, headers={'Origin':'https://evil.example'})[0] == 403
        assert request(base, '/jev?access_token=anything', token=static)[0] == 400
        meta = rpc(request(base, '/.well-known/oauth-protected-resource/jev')[2])
        assert meta['resource'] == 'https://mcp.example/jev'
        assert meta['authorization_servers'] == ['https://mcp.example']
        assert request(base, '/mcp/missing')[0] == 404
        assert request(base, '/mcp/demo')[0] == 404
        assert request(base, '/.well-known/oauth-protected-resource/mcp/demo')[0] == 404
        init = {'jsonrpc':'2.0','id':1,'method':'initialize','params':{'protocolVersion':'2025-11-25','capabilities':{},'clientInfo':{'name':'test','version':'1'}}}
        status, h, body = request(base, '/jev', init, static)
        assert status == 200 and rpc(body)['result']['serverInfo']['name'] == 'mcpmux-demo'
        sid = h['Mcp-Session-Id']
        listing = {'jsonrpc':'2.0','id':2,'method':'tools/list','params':{}}
        status, _, body = request(base, '/jev', listing, static, {'Mcp-Session-Id':sid})
        assert status == 200 and rpc(body)['result']['tools'][0]['name'] == 'echo'
        assert request(base, '/mcp/demo-alias', listing, alias_token, {'Mcp-Session-Id':sid})[0] == 404
        assert request(base, '/jev', {'jsonrpc':'2.0','method':'notifications/initialized'}, static, {'Mcp-Session-Id':sid})[0] == 202
        call = {'jsonrpc':'2.0','id':3,'method':'tools/call','params':{'name':'echo','arguments':{'message':'gateway verified'}}}
        assert rpc(request(base, '/jev', call, static, {'Mcp-Session-Id':sid})[2])['result']['content'][0]['text'] == 'gateway verified'
        assert request(base, '/jev', token=static, headers={'Mcp-Session-Id':sid}, method='DELETE')[0] == 204
        assert request(base, '/jev', listing, static, {'Mcp-Session-Id':sid})[0] == 404
        modern = dict(call, params=dict(call['params'], _meta={'io.modelcontextprotocol/protocolVersion':'2026-07-28','io.modelcontextprotocol/clientInfo':{'name':'test','version':'1'},'io.modelcontextprotocol/clientCapabilities':{}}))
        headers = {'MCP-Protocol-Version':'2026-07-28','Mcp-Method':'tools/call','Mcp-Name':'echo'}
        assert rpc(request(base, '/jev', modern, static, headers)[2])['result']['content'][0]['text'] == 'gateway verified'
        assert request(base, '/jev', modern, static, dict(headers, **{'Mcp-Name':'wrong'}))[0] == 400
        encoded = base64.b64encode(b'echo').decode()
        assert request(base, '/jev', modern, static, dict(headers, **{'Mcp-Name':f'=?base64?{encoded}?='}))[0] == 200
        discover = {'jsonrpc':'2.0','id':5,'method':'server/discover','params':{'_meta':modern['params']['_meta']}}
        discovery = rpc(request(base, '/jev', discover, static, {'MCP-Protocol-Version':'2026-07-28','Mcp-Method':'server/discover'})[2])
        assert discovery['result']['resultType'] == 'complete' and '2026-07-28' in discovery['result']['supportedVersions']
        unknown = dict(discover, method='not/a/method')
        assert request(base, '/jev', unknown, static, {'MCP-Protocol-Version':'2026-07-28','Mcp-Method':'not/a/method'})[0] == 404
        assert request(base, '/jev', modern, static, dict(headers, **{'MCP-Protocol-Version':'2025-11-25'}))[0] == 400
        assert request(base, '/jev', modern, static, dict(headers, **{'MCP-Protocol-Version':'2099-01-01'}))[0] == 400
        # A legacy server request must reach the request SSE stream, and its
        # client response must reach the same isolated stdio process.
        _, askh, _ = request(base, '/mcp/ask', init, ask_token)
        ask_sid = askh['Mcp-Session-Id']
        ask = {'jsonrpc':'2.0','id':10,'method':'test/ask','params':{}}
        req = urllib.request.Request(base+'/mcp/ask', data=json.dumps(ask).encode(), headers={'Authorization':'Bearer '+ask_token,'Content-Type':'application/json','Accept':'application/json, text/event-stream','Mcp-Session-Id':ask_sid})
        with opener.open(req, timeout=5) as stream:
            while True:
                line = stream.readline().decode()
                if line.startswith('data:'):
                    server_request = json.loads(line[5:])
                    break
            assert server_request['method'] == 'sampling/createMessage'
            assert request(base, '/mcp/ask', ask, ask_token, {'Mcp-Session-Id':ask_sid})[0] == 409
            answer = {'jsonrpc':'2.0','id':'server-1','result':{'accepted':True}}
            assert request(base, '/mcp/ask', answer, ask_token, {'Mcp-Session-Id':ask_sid})[0] == 202
            while True:
                line = stream.readline().decode()
                if line.startswith('data:'):
                    assert json.loads(line[5:])['result']['accepted'] is True
                    break
        assert request(base, '/mcp/ask', token=ask_token, headers={'Mcp-Session-Id':ask_sid}, method='DELETE')[0] == 204
        # HTTP upstream credentials and session identifiers must be isolated.
        status, h, _ = request(base, '/mcp/remote', init, remote_access, {'Cookie':'never-forward','Origin':'https://mcp.example'})
        remote_sid = h['Mcp-Session-Id']
        assert status == 200 and remote_sid != 'private-upstream-session'
        assert seen[-1]['authorization'] == 'Bearer ' + remote_token
        assert 'cookie' not in seen[-1] and 'origin' not in seen[-1]
        assert request(base, '/mcp/remote', listing, remote_access, {'Mcp-Session-Id':remote_sid})[0] == 200
        assert seen[-1]['mcp-session-id'] == 'private-upstream-session'
        assert request(base, '/mcp/remote', token=remote_access, headers={'Mcp-Session-Id':remote_sid}, method='DELETE')[0] == 204
        status, h, body = request(base, '/mcp/remote', modern, remote_access, dict(headers, **{'Mcp-Param-Custom':'opaque'}))
        assert status == 200 and 'Mcp-Session-Id' not in h
        events = [json.loads(line[5:]) for line in body.splitlines() if line.startswith('data:')]
        assert len(events) == 2 and events[-1]['result']['ok'] is True
        assert seen[-1]['mcp-param-custom'] == 'opaque'
        assert request(base, '/token', {}, form=True)[0] == 400
        assert request(base, '/jev', b'x'*(1024*1024+1), static, {'Content-Type':'application/json','Accept':'application/json, text/event-stream'})[0] == 413
        # OAuth flow: exact registration, consent, PKCE, resource binding, code replay.
        verifier = 'x' * 43
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')
        authq = {'response_type':'code','client_id':'mcpmux-local','redirect_uri':'http://127.0.0.1:8765/callback','resource':'https://mcp.example/jev','code_challenge':challenge,'code_challenge_method':'S256','scope':'mcp:access','state':'csrf-state'}
        assert request(base, '/authorize?' + urllib.parse.urlencode(dict(authq, redirect_uri='https://evil.example')))[0] == 400
        def get_code():
            status, _, page = request(base, '/authorize?' + urllib.parse.urlencode(authq))
            assert status == 200
            txn = re.search("name=transaction value='([^']+)'", page).group(1)
            status, h, _ = request(base, '/authorize', {'transaction':txn,'username':'owner','password':password}, form=True)
            assert status == 303
            qs = urllib.parse.parse_qs(urllib.parse.urlparse(h['Location']).query)
            assert qs['state'] == ['csrf-state'] and qs['iss'] == ['https://mcp.example']
            return qs['code'][0]
        exchange = {'grant_type':'authorization_code','code':get_code(),'client_id':'mcpmux-local','redirect_uri':authq['redirect_uri'],'resource':authq['resource'],'code_verifier':verifier}
        assert request(base, '/token', dict(exchange, resource='https://mcp.example/mcp/demo-alias'), form=True)[0] == 400
        exchange['code'] = get_code()
        assert request(base, '/token', dict(exchange, code_verifier='z'*43), form=True)[0] == 400
        exchange['code'] = get_code()
        status, _, body = request(base, '/token', exchange, form=True)
        assert status == 200
        oauth = rpc(body)['access_token']
        assert request(base, '/token', exchange, form=True)[0] == 400
        assert request(base, '/jev', modern, oauth, headers)[0] == 200
        assert request(base, '/mcp/demo-alias', modern, oauth, headers)[0] == 401
        print('PASS: stdio legacy/modern, aliases, HTTP streaming/session isolation, credential separation, Origin, scopes, OAuth PKCE/resource binding/replay')
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
up.shutdown()
