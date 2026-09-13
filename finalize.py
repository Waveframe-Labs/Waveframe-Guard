"""Verify retained final-head results and write the downstream package selection."""
import hashlib,json,pathlib,subprocess,zipfile,xml.etree.ElementTree as ET
ROOT=pathlib.Path(__file__).resolve().parent
HEAD=subprocess.check_output(['git','rev-parse','HEAD']).decode().strip()
BASE='0161ef8a52e052d1bc1366cdc93ce13a9bd535ed'
LEDGER='a34c11d81b85963794cf28b4adad091fac15e130'
COMPILER='ae590dee058d3481e384dea850d5b7d980f533ff'

def read(p):return json.loads(p.read_text(encoding='utf-8'))
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def write(p,v):p.write_text(json.dumps(v,indent=2)+'\n',encoding='utf-8')
def origin_sha(origin):
 a=origin['archive_info'];return a.get('hashes',{}).get('sha256') or a['hash'].removeprefix('sha256=')
def suite(path):
 cases=ET.parse(path).findall('.//testcase')
 counts={k:sum(c.find(tag) is not None for c in cases) for k,tag in [('skipped','skipped'),('failures','failure'),('errors','error')]}
 counts['passed']=len(cases)-sum(counts.values());assert counts['failures']==counts['errors']==0
 release=[c for c in cases if '[release' in c.get('name','') or c.get('classname','').endswith('test_release_catalog')]
 assert len(release)==150 and all(c.find('skipped') is None for c in release)
 counts['release_passed']=len(release);return counts
runs=[]
for p in sorted((ROOT/'ci').glob('*/run.json')):
 r=read(p)
 if r['head_sha']!=HEAD:continue
 assert r['status']=='completed' and r['conclusion']=='success'
 jobs=read(p.parent/'jobs.json')['jobs'];assert all(j['status']=='completed' and j['conclusion']=='success' for j in jobs)
 runs.append({'id':r['id'],'url':r['html_url'],'head':HEAD,'conclusion':'success','jobs':[{'name':j['name'],'url':j['html_url'],'conclusion':j['conclusion']} for j in jobs]})
assert len(runs)==2 and sum(len(r['jobs']) for r in runs)==11
action_run=next(r['id'] for r in runs if len(r['jobs'])==4)
manifest={'schema':'guard-issue52-package-set-v1','guard_head':HEAD,'guard_base':BASE,'guard_base_branch':'feat/50-guard-019-release','pr':'https://github.com/Waveframe-Labs/Waveframe-Guard/pull/53','ledger_head':LEDGER,'compiler_head':COMPILER,'ledger_archive_evidence_commit':'46cd4c5a9a2c17e2367d64b56803df92de69d8b3','cloud_regression_server':'547291b525e2f1d05d92ed65b6058c4ca91588a8','cloud_next_base':'8552aad2fc4fcf861cc2205ebce70a5b486534e6','release_ready':False,'runtime_activation_ready':False,'ci':runs,'cells':{},'recommended_cloud_cell':'ubuntu-3.14','scope':'Current validated Guard wheel set. Cloud must consume this set for package/Console/production-image acceptance above #151. Connected results here are retained catalog-2 regression only. No deployment or activation.','historical_inputs':'Guard #49/#51 and Ledger #24 evidence remain historical; the verified Ledger #26 archives include old Guard #51 results but current tests name this new Guard head. Supplemental local checkout evidence is excluded from package selection.'}
for osname in ('ubuntu','windows'):
 for py in ('3.10','3.14'):
  cell=f'{osname}-{py}'; folder=f'{action_run}/action-policy-{osname}-latest-{py}'; root=ROOT/'cells'/folder
  assert (root/'guard-head.txt').read_text().strip()==HEAD
  package=root/'package'; build=read(package/'build-provenance.json'); candidate=read(package/'guard-candidate.json')
  assert candidate['source_commit']==build['source_commit']==HEAD and build['build_exit_code']==0 and build['clean_tracked_checkout']
  hashes=read(package/'package-hashes.json')
  for name,digest in hashes.items():assert sha(package/name)==digest
  wheel=package/candidate['wheel'];assert sha(wheel)==candidate['wheel_sha256']
  coordination=read(root/'ledger-extra/guard-coordination.json'); combined=read(root/'ledger-extra/combined/acceptance.json')
  assert coordination['status']=='passed' and coordination['guard_head']==HEAD and coordination['ledger_head']==LEDGER
  assert combined['status']=='combined-extra-passed' and combined['head']==HEAD
  assert combined['guard_candidate']==candidate and coordination['guard_candidate']==candidate
  assert len(coordination['source_archive_equivalence'])==3 and all(v['runtime_resources_equal'] for v in coordination['source_archive_equivalence'].values())
  for mode,n,skips in [('default',678,44),('native',722,0)]:
   c=combined['suites']['combined-extra-'+mode];assert c['passed']==n and c['skipped']==skips and c['release_passed']==70
  assert combined['catalog_3_execution_cases']==56
  assert coordination['guard_entry_upgrade']==coordination['old_ledger_resolver_rejection']=='passed'
  for cmd in combined['commands']:
   assert cmd['exit_code']==0 or cmd['label'].startswith('reject-old-ledger-'),cmd
  ordinary=read(root/'ledger-extra/combined/combined-provenance.json')
  upgrade=read(root/'ledger-extra/combined/guard-entry-provenance.json')
  assert ordinary['distributions']['waveframe-guard']['wheel_sha256']==upgrade['distributions']['waveframe-guard']['wheel_sha256']==candidate['wheel_sha256']
  connected=read(root/'connected/summary.json')
  assert len(connected['outcomes'])==23 and connected['server']['source_clean']
  assert connected['server']['cloud_commit']==manifest['cloud_regression_server']
  assert connected['dependencies']['governance-ledger']['vcs_info']['commit_id']==LEDGER
  assert connected['dependencies']['cricore-contract-compiler']['vcs_info']['commit_id']==COMPILER
  if connected['guard_pep610']['archive_info']:
   assert origin_sha(connected['guard_pep610'])==candidate['wheel_sha256']
  installed=read(root/'connected/client-install.json')
  installed_guard,=[e for e in installed['install'] if e['metadata']['name']=='waveframe-guard']
  assert origin_sha(installed_guard['download_info'])==candidate['wheel_sha256']
  assert installed_guard['download_info']['url']==connected['guard_pep610']['url']
  for name in ('client','server'):assert 'No broken requirements found' in (root/f'connected/{name}-pip-check.txt').read_text()
  selection={}
  for name,digest in coordination['package_sha256'].items():
   p=root/'ledger-extra/wheelhouse'/name;assert sha(p)==digest
   selection[name]={'sha256':digest,'member':f'ledger-extra/wheelhouse/{name}'}
  sdist,=[n for n in hashes if n.endswith('.tar.gz')]
  selection[sdist]={'sha256':hashes[sdist],'member':f'package/{sdist}'}
  archive=ROOT/'artifacts'/f'{folder}.zip'
  manifest['cells'][cell]={'python':build['python'],'guard_suites':{'source_default':suite(root/'default.xml'),'source_development':suite(root/'development.xml'),'installed_default':suite(package/'installed-release.xml'),'installed_development':suite(package/'installed-development.xml')},'combined_suites':combined['suites'],'catalog_3_execution_cases':56,'connected_cases':23,'connected_guard_hash_source':'actual client-install.json archive_info; direct_url hash additionally checked where present','connected_scope':'Unchanged Cloud #147 catalog-2 regression; independent server interpreter/dependencies','archive':archive.relative_to(ROOT).as_posix(),'archive_sha256':sha(archive),'packages':selection,'ledger_compiler_archive_origin':coordination['archive_origin'],'compiler_build_origin':coordination['compiler_build'],'guard_build_record':f'cells/{folder}/package/build-provenance.json','install_provenance':f'cells/{folder}/ledger-extra/combined/combined-provenance.json','upgrade_provenance':f'cells/{folder}/ledger-extra/combined/guard-entry-provenance.json','source_archive_equivalence':coordination['source_archive_equivalence'],'mount_equivalence':coordination['mount_equivalence']}
assert sum(c['connected_cases'] for c in manifest['cells'].values())==92
selected=manifest['cells']['ubuntu-3.14']
manifest['cloud_package_selection']={k:selected[k] for k in ('archive','archive_sha256','packages')}
manifest['metadata']={'guard':'0.19.0','proposed_tag':'v0.19.0 (not created)','ledger_runtime':'>=0.9.0,<0.10.0','compiler_test_development':'>=0.5.0,<0.6.0','cri_runtime':'>=0.13.0,<0.15.0','normalizer_runtime':'>=0.2.0,<0.3.0','requests_runtime':'>=2.33.0,<3.0.0','python':'>=3.10'}
manifest['mount_build_input_equivalence']='mount-build-input-equivalence.json'
manifest['release_order']=['Compiler 0.5.0','Ledger 0.9.0','Guard 0.19.0','ordinary index checks','separately authorized Cloud rollout/activation']
write(ROOT/'package-set.json',manifest)
write(ROOT/'handoff.json',{'package_set':'package-set.json','package_set_sha256':sha(ROOT/'package-set.json'),'head':HEAD,'base':BASE,'pr':manifest['pr'],'release_ready':False})
print(json.dumps({k:v['guard_suites'] for k,v in manifest['cells'].items()},indent=2))
