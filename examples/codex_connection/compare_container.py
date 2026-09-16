"""Bounded Linux/WSL2 comparison, NOT a native-Windows or real-Codex proof."""
import argparse
import json
from pathlib import Path
import subprocess
import time
from uuid import uuid4


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    calls = []

    def run(command):
        start = time.monotonic()
        result = subprocess.run(command, text=True, capture_output=True)
        calls.append({"argv": command, "exit_code": result.returncode,
                      "seconds": round(time.monotonic() - start, 2),
                      "stdout": result.stdout, "stderr": result.stderr})
        (output / "commands.json").write_text(json.dumps(calls, indent=2))
        if result.returncode:
            raise RuntimeError(f"Comparison command failed; see {output}")
        return result.stdout

    image = "waveframe-guard-54-proof:local"
    volume = "waveframe-guard-54-" + uuid4().hex[:8]
    run(["docker", "version", "--format", "{{json .}}"])
    run(["docker", "build", "-f", "examples/codex_connection/Dockerfile.comparison", "-t", image, "."])
    run(["docker", "volume", "create", "--label", "waveframe.issue=54", volume])
    (output / "resources.json").write_text(json.dumps({"image": image, "volume": volume}))
    run(["docker", "run", "--rm", "--network", "none", "--user", "0:0", "-v", volume + ":/repo", image,
         "python", "-I", "-c", "import os; from pathlib import Path; p=Path('/repo'); (p/'generated').mkdir(); (p/'README.md').write_text('before'); os.chown(p,10001,10001); os.chown(p/'generated',10001,10001); os.chown(p/'README.md',10001,10001)"])
    common = ["docker", "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL",
              "--security-opt", "no-new-privileges:true"]
    writer = """import sys,json
from pathlib import Path
sys.path.insert(0,'/opt/proof')
from writer import Writer
w=Writer(Path('/repo'),Path('/evidence'),Path('/opt/proof/publication'))
results=[w.write(dict(action=a,path=p,content=c)) for a,p,c in [('create','generated/new.md','created'),('modify','README.md','modified'),('create','blocked.md','denied')]]
assert [r['outcome'] for r in results]==['executed','executed','blocked'], results
saved={}
for a,g in w.guards.items():
 for p in g.workspace.rglob('*.json'): saved[a+'/'+str(p.relative_to(g.workspace))]=json.loads(p.read_text())
print(json.dumps({'results':results,'saved_artifacts':saved}))
w.close()
"""
    run(common + ["--user", "10001:10001", "--mount", "type=volume,src=" + volume + ",dst=/repo",
                  "--tmpfs", "/evidence:uid=10001,gid=10001,mode=700", image, "python", "-I", "-c", writer])
    agent = """import os,json,subprocess
from pathlib import Path
r={'uid':os.getuid(),'pids':[p.name for p in Path('/proc').iterdir() if p.name.isdigit()]}
for label,fn in [('create',lambda:Path('/repo/bypass').write_text('x')),('modify',lambda:Path('/repo/README.md').write_text('x')),('chmod',lambda:os.chmod('/repo/README.md',0o777)),('writer_code',lambda:Path('/opt/proof/writer.py').write_text('x'))]:
 try: fn(); r[label]='GAP'
 except OSError as e:r[label]={'errno':e.errno}
c=subprocess.run(['python','-I','-c',"from pathlib import Path; Path('/repo/child').write_text('x')"],capture_output=True,text=True)
r['child']={'exit':c.returncode,'stderr':c.stderr}
Path('/scratch/output').write_text('scratch')
r['scratch']=Path('/scratch/output').read_text()
r['bytes']={str(p.relative_to('/repo')):p.read_bytes().hex() for p in Path('/repo').rglob('*') if p.is_file()}
assert all(r[k]!='GAP' for k in ['create','modify','chmod','writer_code']) and c.returncode!=0
assert r['bytes']=={'README.md':b'modified'.hex(),'generated/new.md':b'created'.hex()}
print(json.dumps(r))
"""
    # Writer container has exited: connector unavailable throughout these attempts.
    # Guard creates files as 0600. Matching the container UID permits reads;
    # the read-only mount and separate PID namespace provide the separation.
    run(common + ["--user", "10001:10001", "--mount", "type=volume,src=" + volume + ",dst=/repo,readonly",
                  "--tmpfs", "/scratch:uid=10001,gid=10001,mode=700", image, "python", "-I", "-c", agent])
    run(["docker", "image", "inspect", image, "--format", "{{json .}}"])
    print(output)


if __name__ == "__main__":
    main()
