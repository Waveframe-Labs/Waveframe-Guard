from pathlib import Path
import json, subprocess, hashlib
out=Path('acceptance-output/release50-mount');out.mkdir(exist_ok=True)
wheel=Path('acceptance-output/release50-local-package3/waveframe_guard-0.19.0-py3-none-any.whl')
command=['docker','run','--rm','--cap-add','SYS_ADMIN','--security-opt','seccomp=unconfined','--tmpfs','/tmp:exec,mode=1777','--mount','type=bind,source=C:/GitHub/Waveframe-Guard,target=/guard,readonly','python@sha256:656d12e70054d5fda18a045e2494c96701e9792dd1445f95b3d038df954f57e9','python','/guard/.candidate48/mount.py','/guard/'+wheel.as_posix()]
report={'command':command,'guard_head':subprocess.check_output(['git','rev-parse','HEAD']).decode().strip(),'wheel_sha256':hashlib.sha256(wheel.read_bytes()).hexdigest(),'runner_sha256':hashlib.sha256(Path('.candidate48/mount.py').read_bytes()).hexdigest()}
(out/'command.json').write_text(json.dumps(report,indent=2))
with (out/'output.log').open('w',encoding='utf-8') as log:r=subprocess.run(command,stdout=log,stderr=subprocess.STDOUT)
report['exit_code']=r.returncode
(out/'command.json').write_text(json.dumps(report,indent=2))
raise SystemExit(r.returncode)
