"""Export only observed governed bytes and verify on another disposable base copy."""
import hashlib
import json
from pathlib import Path
import subprocess

import run

COMPILER_HEAD = 'f817a1bca65806c9ee33ccc74c2238952ebf8f01'
ALLOWED = {'README.md', 'examples/compile_repository_policy.py'}


def sha(data): return hashlib.sha256(data).hexdigest()


def changed_paths(before, after):
    changed = {p for p in before.keys() | after.keys() if before.get(p) != after.get(p)}
    assert changed == ALLOWED, changed
    assert set(before) <= set(after), 'Deletion is outside this trial'
    assert 'examples/compile_repository_policy.py' not in before
    return changed


def git(root, *args):
    return subprocess.check_output(['git', '-c', 'core.autocrlf=false', '-c', 'core.safecrlf=false',
        '-c', 'core.hooksPath=/nonexistent-compiler-trial-hooks', '-C', str(root), *args], stderr=subprocess.PIPE)


def materialize(root, snapshot):
    root.mkdir(parents=True, exist_ok=False)
    for name, value in snapshot.items():
        path = Path(name)
        assert not path.is_absolute() and '..' not in path.parts and '.git' not in path.parts
        data = bytes.fromhex(value['bytes'])
        assert sha(data) == value['sha256']
        target = root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    git(root, 'init', '-q')


def export(repository, output, before, after):
    changed = changed_paths(before, after)
    # Independently bind every starting byte to the exact pinned repository objects.
    for path, value in before.items():
        assert git(repository, 'show', COMPILER_HEAD + ':' + path) == bytes.fromhex(value['bytes'])
    work = output / 'export-work'
    applied = output / 'apply-check'
    materialize(work, before)
    git(work, 'add', '.')
    for name in sorted(changed):
        target = work / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(bytes.fromhex(after[name]['bytes']))
    git(work, 'add', '-N', 'examples/compile_repository_policy.py')
    patch = git(work, 'diff', '--binary', '--full-index', '--no-ext-diff', '--no-textconv', '--', *sorted(changed))
    assert patch and b'new file mode 100644' in patch
    preamble = ('Compiler documentation/example trial\nBase-commit: ' + COMPILER_HEAD + '\n\n').encode()
    artifact = output / 'compiler-documentation.patch'
    artifact.write_bytes(preamble + patch)
    materialize(applied, before)
    git(applied, 'apply', '--check', str(artifact))
    git(applied, 'apply', str(artifact))
    found = {p.relative_to(applied).as_posix(): sha(p.read_bytes()) for p in applied.rglob('*')
             if p.is_file() and '.git' not in p.relative_to(applied).parts}
    assert found == {k: v['sha256'] for k, v in after.items()}
    command = ['run', '--rm', *run.security(), '--mount', f'type=bind,source={applied.resolve()},target=/source,readonly',
        '--entrypoint', 'python', run.IMAGE, '-I', '-c',
        "import sys,runpy; sys.path.insert(0,'/source/src'); runpy.run_path('/source/examples/compile_repository_policy.py',run_name='__main__')"]
    result = run.docker(*command)
    assert result.stdout == (output / 'validation/example-source.stdout.txt').read_bytes()
    (output / 'patch-example.stdout.txt').write_bytes(result.stdout)
    record = {'compiler_base': COMPILER_HEAD, 'compiler_tree': git(repository, 'rev-parse', COMPILER_HEAD + '^{tree}').decode().strip(),
        'patch_sha256': sha(artifact.read_bytes()), 'patch_bytes': artifact.stat().st_size,
        'changed_paths': sorted(changed), 'new_file_included': True,
        'base_file_hashes': {k: v['sha256'] for k, v in before.items()}, 'applied_file_hashes': found,
        'applied_bytes_equal_governed_workspace': True, 'apply_check_passed': True,
        'example_stdout_sha256': sha(result.stdout), 'example_command': ['docker', *command],
        'sibling_working_tree_modified': False, 'target': 'another disposable operator copy; never the input checkout'}
    run.save(output / 'patch-verification.json', record)
    return record
