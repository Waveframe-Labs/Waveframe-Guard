"""Install the exact native npm distribution used by the 0.154.0 launcher."""
import base64
import hashlib
import io
import json
from pathlib import Path
import tarfile
import urllib.request

url = 'https://registry.npmjs.org/@openai/codex/-/codex-0.154.0-linux-x64.tgz'
expected = 'a4FI3A8sGtwGrOqltrPbrS2hajrHQG591EwmRfiRoLMb10VxdBtUGW4gu6IJVYENiYGA7k3P4jlRHEoCZU/s9Q=='
data = urllib.request.urlopen(url).read()
assert base64.b64encode(hashlib.sha512(data).digest()).decode() == expected
root = Path('/opt/codex')
with tarfile.open(fileobj=io.BytesIO(data)) as archive:
    archive.extractall(root, filter='data')
binary = next(p for p in root.rglob('codex') if p.is_file())
Path('/usr/local/bin/codex').symlink_to(binary)
rg = next(p for p in root.rglob('rg') if p.is_file())
Path('/usr/local/bin/rg').symlink_to(rg)
Path('/opt/proof/client-provenance.json').write_text(json.dumps({
    'version': '0.154.0', 'url': url, 'npm_integrity': 'sha512-' + expected,
    'archive_sha256': hashlib.sha256(data).hexdigest(),
    'binary': str(binary), 'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
}, indent=2))
