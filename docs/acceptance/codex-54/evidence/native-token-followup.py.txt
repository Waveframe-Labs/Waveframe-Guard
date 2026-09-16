import json, subprocess, time
from pathlib import Path
import sys
sys.path.insert(0, 'C:/GitHub/Waveframe-Guard-54/examples/codex_connection')
from launch import toml, snapshot
root = Path('C:/Users/swrig/AppData/Local/Waveframe/issue54/final')
c = json.loads((root/'connection.json').read_text())
output = root/'capture/native-token-followup'
output.mkdir()
before = snapshot(Path(c['workspace']))
start = time.time()
writer_args = [c['python'], '-I', c['writer'], '--root', c['workspace'], '--evidence', c['guard_evidence'], '--publication', c['publication']]
with subprocess.Popen(writer_args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=Path(c['writer']).parent, close_fds=True) as writer:
    metadata = Path(c['guard_evidence'])/'process-probe.json'
    while (not metadata.exists() or metadata.stat().st_mtime < start) and time.time()-start < 15:
        time.sleep(0.1)
    pid = json.loads(metadata.read_text())['pid']
    args = [c['codex'], 'sandbox', '-P', 'waveframe', '-c', 'windows.sandbox="elevated"', '-c', 'permissions.waveframe='+toml({'extends': ':read-only','filesystem':{c['scratch']:'write'}}), '-C', c['workspace'], c['python'], '-I', c['probe'], str(root/'connection.json'), '--writer-pid', str(pid)]
    (output/'argv.json').write_text(json.dumps(args,indent=2))
    result = subprocess.run(args, capture_output=True, text=True, encoding='utf-8')
    (output/'stdout.txt').write_text(result.stdout)
    (output/'stderr.txt').write_text(result.stderr)
    writer_stdout, writer_stderr = writer.communicate()
    (output/'writer-stderr.txt').write_bytes(writer_stderr)
after = snapshot(Path(c['workspace']))
(output/'inspection.json').write_text(json.dumps({'before': before, 'after': after,'exit_code': result.returncode,'changed':[k for k in before.keys()|after.keys() if before.get(k)!=after.get(k)]},indent=2))
print(result.returncode)
print(result.stdout[-1500:])
print(result.stderr[-500:])
