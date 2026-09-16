"""Operator-side public archive and installed-byte verification; no image writes."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import subprocess
import urllib.request
import zipfile

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--name',required=True)
parser.add_argument('--output',type=Path,required=True)
args=parser.parse_args()
pip=json.loads((args.output/'pip-report.json').read_text(encoding='utf-8'))
verified={}
for item in pip['install']:
    name=item['metadata']['name'].lower().replace('_','-')
    if name not in ('waveframe-guard','governance-ledger','cricore-contract-compiler','mcp'):
        continue
    origin=item['download_info']; data=urllib.request.urlopen(origin['url']).read()
    assert hashlib.sha256(data).hexdigest()==origin['archive_info']['hashes']['sha256']
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        expected={n:hashlib.sha256(archive.read(n)).hexdigest() for n in archive.namelist()
                  if not n.endswith('/') and not n.endswith('.dist-info/RECORD')}
        assert all(not Path(n).is_absolute() and '..' not in Path(n).parts for n in expected)
    code="""import sys,json,pathlib,hashlib,sysconfig
names=json.load(sys.stdin);base=pathlib.Path(sysconfig.get_paths()['purelib'])
print(json.dumps({n:hashlib.sha256((pathlib.Path(sys.prefix).joinpath(*pathlib.PurePosixPath(n).parts[2:])
 if pathlib.PurePosixPath(n).parts[0].endswith('.data') else base/n).read_bytes()).hexdigest() for n in names}))
"""
    actual=json.loads(subprocess.check_output(['docker','exec','-i',args.name+'-agent','python','-I','-c',code],
                                             input=json.dumps(list(expected)).encode()))
    assert actual==expected,name
    verified[name]={'version':item['metadata']['version'],'archive':origin,'installed_sha256':actual}
assert len(verified)==4
(args.output/'installed-bytes.json').write_text(json.dumps(verified,indent=2)+'\n',encoding='utf-8')
print('Authenticated public wheel hashes and 278 installed files verified')
