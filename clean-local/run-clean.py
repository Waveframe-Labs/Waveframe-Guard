import json,pathlib,subprocess,sys
root=pathlib.Path('.candidate52/clean-guard').resolve();out=pathlib.Path('acceptance-output/issue52-clean-local').resolve();out.mkdir(parents=True,exist_ok=True)
commands=[('package',[str(pathlib.Path('.venv/Scripts/python.exe').resolve()),'tools/acceptance/release_catalog_package.py','--output',str(out/'package')]),('combined',[str(pathlib.Path('.venv/Scripts/python.exe').resolve()),'tools/acceptance/ledger_guard_extra.py','--ledger-source',str(pathlib.Path('.candidate52/ledger').resolve()),'--guard-candidate',str(out/'package/guard-candidate.json'),'--output',str(out/'ledger-extra'),'--dependency-snapshot',str(out/'package/installed-dependencies.json')])]
record=[]
for label,command in commands:
 with (out/f'{label}.log').open('w',encoding='utf-8') as log:r=subprocess.run(command,cwd=root,stdout=log,stderr=subprocess.STDOUT)
 record.append({'command':command,'cwd':str(root),'exit_code':r.returncode});(out/'commands.json').write_text(json.dumps(record,indent=2)+'\n')
 if r.returncode:sys.exit(r.returncode)
