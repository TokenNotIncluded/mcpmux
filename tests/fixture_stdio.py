import json
import sys
pending = None
for line in sys.stdin:
    v = json.loads(line)
    def send(value):
        print(json.dumps(value), flush=True)
    if v.get('method') == 'initialize':
        send({'jsonrpc':'2.0','id':v['id'],'result':{'protocolVersion':'2025-11-25','capabilities':{},'serverInfo':{'name':'fixture','version':'1'}}})
    elif v.get('method') == 'test/ask':
        pending = v['id']
        send({'jsonrpc':'2.0','id':'server-1','method':'sampling/createMessage','params':{'messages':[],'maxTokens':1}})
    elif v.get('id') == 'server-1' and 'result' in v:
        send({'jsonrpc':'2.0','id':pending,'result':v['result']})
    elif v.get('method') == 'test/progress':
        send({'jsonrpc':'2.0','method':'notifications/progress','params':{'progressToken':'test','progress':1}})
        send({'jsonrpc':'2.0','id':v['id'],'result':{}})
