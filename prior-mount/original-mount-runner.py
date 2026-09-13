import subprocess, sys, platform, pathlib, xml.etree.ElementTree as ET, shutil, os, hashlib, json
print(platform.platform(), sys.version, flush=True)
print(pathlib.Path('/proc/self/uid_map').read_text(), flush=True)
wheel = sys.argv[1]
print('wheel_sha256='+hashlib.sha256(pathlib.Path(wheel).read_bytes()).hexdigest(), flush=True)
subprocess.run(['apt-get','update','-qq'],check=True)
subprocess.run(['apt-get','install','-y','-qq','git'],check=True)
subprocess.run([sys.executable, '-m', 'pip', 'install', wheel, 'pytest', '-r','/guard/.github/requirements/action-policy-release.txt'], check=True)
subprocess.run([sys.executable,'-m','pip','check'],check=True)
from importlib.metadata import distribution
for name in ('governance-ledger','cricore-contract-compiler'):
    print(name, distribution(name).read_text('direct_url.json'),flush=True)
for name in ('tests','tools'):
    shutil.copytree('/guard/'+name, '/tmp/acceptance/'+name)
env = dict(os.environ, GUARD_EXPECT_INSTALLED='1')
subprocess.run([sys.executable, '-m', 'pytest', '-q', '-ra', '-p', 'no:cacheprovider', 'tests/test_repository_workspace.py::test_same_device_bind_mount_rejected_where_namespaces_available', '--junitxml=/tmp/mount.xml'], check=True, cwd='/tmp/acceptance', env=env)
print(pathlib.Path('/tmp/mount.xml').read_text(), flush=True)
cases = ET.parse('/tmp/mount.xml').findall('.//testcase')
assert len(cases)==1 and all(c.find('skipped') is None for c in cases), 'mount case unavailable; not a pass'
