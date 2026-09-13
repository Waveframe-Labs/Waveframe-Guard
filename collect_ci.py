"""Retain completed CI runs and authenticated artifact ZIPs without changing the candidate."""
import hashlib,json,pathlib,subprocess,sys,zipfile
root=pathlib.Path(__file__).resolve().parent
repo='Waveframe-Labs/Waveframe-Guard'

def gh(*args):
 return subprocess.check_output(['gh',*args])
def save(path,data):
 path.parent.mkdir(parents=True,exist_ok=True); path.write_bytes(data)
def write(path,data):
 save(path,(json.dumps(data,indent=2)+'\n').encode())
head=__import__('os').environ.get('EXPECTED_GUARD_HEAD') or subprocess.check_output(['git','rev-parse','HEAD']).decode().strip()
for run_id in sys.argv[1:]:
 run=json.loads(gh('api',f'repos/{repo}/actions/runs/{run_id}'))
 assert run['head_sha']==head
 assert run['status']=='completed',run['status']
 write(root/f'ci/{run_id}/run.json',run)
 jobs=json.loads(gh('api',f'repos/{repo}/actions/runs/{run_id}/jobs?per_page=100'))
 write(root/f'ci/{run_id}/jobs.json',jobs)
 listing=json.loads(gh('api',f'repos/{repo}/actions/runs/{run_id}/artifacts?per_page=100'))
 write(root/f'ci/{run_id}/artifacts.json',listing)
 log=root/f'ci/{run_id}/logs.zip'
 if not log.exists(): save(log,gh('api',f'repos/{repo}/actions/runs/{run_id}/logs'))
 for item in listing['artifacts']:
  assert item['workflow_run']['head_sha']==head
  path=root/f'artifacts/{run_id}/{item["name"]}.zip'
  if not path.exists(): save(path,gh('api',f'repos/{repo}/actions/artifacts/{item["id"]}/zip'))
  actual=hashlib.sha256(path.read_bytes()).hexdigest()
  assert item['digest']=='sha256:'+actual,(path,actual,item['digest'])
  with zipfile.ZipFile(path) as z:
   z.extractall(root/f'cells/{run_id}/{item["name"]}')
  print(item['name'],actual,path.stat().st_size,flush=True)
print('Completed retention')
