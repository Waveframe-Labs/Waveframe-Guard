"""Supplemental raw-frame observation of the same private MCP transport."""
import argparse
import json
from pathlib import Path
import subprocess

from run import writer, snapshot, save, docker

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--name', required=True)
parser.add_argument('--output', type=Path, required=True)
parser.add_argument('--cloud', action='store_true')
args = parser.parse_args()
if args.cloud:
    from run_cloud import writer as cloud_writer
    def writer(name, mode='normal'):
        return cloud_writer(name, mode=mode)
before = snapshot(args.name)
probe = r'''
import json,socket,sys,time
mode=sys.argv[1]; s=socket.socket(socket.AF_UNIX); s.settimeout(3); s.connect('/ipc/mcp.sock'); f=s.makefile('rwb',buffering=0)
frames=[]
def send(value):
 raw=(json.dumps(value)+'\n').encode(); frames.append({'sent':raw.decode()});f.write(raw)
def read(ident):
 while True:
  raw=f.readline();frames.append({'received':raw.decode()})
  if mode=='malformed' and raw==b'not-json\n':return raw
  try: value=json.loads(raw)
  except ValueError:return raw
  if value.get('id')==ident:return value
send({'jsonrpc':'2.0','id':1,'method':'initialize','params':{'protocolVersion':'2025-03-26','capabilities':{},'clientInfo':{'name':'supplemental-raw-transport','version':'1'}}});read(1)
send({'jsonrpc':'2.0','method':'notifications/initialized'})
start=time.monotonic();send({'jsonrpc':'2.0','id':2,'method':'tools/call','params':{'name':'connection_status','arguments':{}}})
try:
 result=read(2); outcome=('malformed-frame' if result else 'unexpected-eof') if isinstance(result,bytes) else 'response'
except TimeoutError: outcome='timeout'
print(json.dumps({'scope':'supplemental deterministic MCP frame capture, not model chat','mode':mode,'outcome':outcome,'elapsed_seconds':round(time.monotonic()-start,3),'frames':frames}))
'''
result = {}
for mode in ('malformed', 'timeout'):
    writer(args.name, mode)
    r = docker('exec', args.name + '-agent', 'python', '-I', '-c', probe, mode)
    result[mode] = json.loads(r.stdout)
    save(args.output, {'before': before, 'results': result})
    assert result[mode]['outcome'] == ('malformed-frame' if mode == 'malformed' else 'timeout'), result[mode]
writer(args.name, 'normal')
after = snapshot(args.name)
assert before == after
save(args.output, {'before': before, 'after': after, 'results': result})
print('Raw malformed frame and 3-second timeout observed; source unchanged')
