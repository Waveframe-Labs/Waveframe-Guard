"""Fixed operator bindings around released Guard.cloud; never execute workspace code."""
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
from uuid import uuid4

from waveframe_guard import Guard


def now():
    return datetime.now(timezone.utc).isoformat()


class Writer:
    def __init__(self, root, evidence, config):
        self.root, self.evidence = Path(root), Path(evidence)
        self.guards, self.loaded_at, self.last_preservation = {}, {}, {}
        self.organization_id = config['organization_id']
        self.runtime_ids = {action: binding['runtime_id'] for action, binding in config['bindings'].items()}
        self.evidence.mkdir(parents=True, exist_ok=True)
        self.lock = (self.evidence / 'writer.lock').open('a')
        # All MCP connections share this operator-owned filesystem lock.
        if config['cloud_url'] != 'http://127.0.0.1:18081':
            raise ValueError('This local-only proof requires the private socket relay endpoint')
        try:
            for action, role in (('create', 'repository-maintainer'), ('modify', 'security-reviewer')):
                binding = config['bindings'][action]
                if binding['actor']['role'] != role:
                    raise ValueError('explicit separate create/modify roles required')
                guard = Guard.cloud(
                    authority=config['authority'], cloud_url=config['cloud_url'],
                    cloud_organization_id=config['organization_id'],
                    runtime_credential=binding['credential'], runtime_id=binding['runtime_id'],
                    environment='development', actor_identity=binding['actor'],
                    repository_root=self.root, workspace=self.evidence / action,
                    execution_context={'surface': 'contained-codex-57'},
                    preservation_timeout_seconds=3,
                )
                self.guards[action] = guard
                loaded = guard.boundary_for().loaded_authority
                if loaded.publication_id != config['publication_id'] or loaded.contract_hash != config['contract_hash']:
                    raise ValueError('loaded publication differs from operator selection')
                if not guard.runtime_connection.ok:
                    raise ValueError('runtime connection rejected; writer not activated')
                self.loaded_at[action] = now()
        except BaseException:
            self.close()
            raise

    def close(self):
        for guard in self.guards.values():
            guard.close()
        self.lock.close()

    def status(self):
        policies = {}
        for action, guard in self.guards.items():
            loaded = guard.boundary_for().loaded_authority
            policies[action] = {
                'authority': loaded.authority_ref, 'publication_id': loaded.publication_id,
                'contract_hash': loaded.contract_hash, 'bundle_hash': loaded.bundle_hash,
                'actor_identity': guard.actor_identity,
                'runtime_id': self.runtime_ids[action], 'organization_id': self.organization_id,
                'contract_version': loaded.contract['contract_version'],
                'loaded_at': self.loaded_at[action],
                'last_successful_preservation': self.last_preservation.get(action),
            }
        return {'connection': 'responding', 'writer_pid': os.getpid(), 'observed_at': now(),
                'cloud_availability': 'not_probed_by_status', 'policies': policies,
                'preservation_observation_scope': 'this writer session only; prior sessions remain in operator evidence',
                'validation_boundary': 'Cloud publication loaded at writer session startup; cached in this Guard instance. No per-write online revocation check.',
                'automatic_retry': False}

    def journal(self, entry):
        with (self.evidence / 'requests.jsonl').open('a', encoding='utf-8') as stream:
            stream.write(json.dumps(entry) + '\n')
            stream.flush()
            os.fsync(stream.fileno())

    def write(self, request):
        if (not isinstance(request, dict) or set(request) != {'action', 'path', 'content'}
                or any(not isinstance(v, str) for v in request.values())
                or request['action'] not in self.guards
                or len(request['content'].encode('utf-8')) > 65536):
            return {'outcome': 'invalid_request', 'mutation_status': 'not_performed', 'automatic_retry': False}
        fcntl.flock(self.lock, fcntl.LOCK_EX)
        try:
            return self._write(request)
        finally:
            fcntl.flock(self.lock, fcntl.LOCK_UN)

    def _write(self, request):
        action = request['action']
        guard = self.guards[action]
        content = request['content'].encode('utf-8')
        normalized = {'schema_version': 'normalized_execution_request.v1', 'request_id': 'codex57-' + uuid4().hex,
                      'action': action, 'target': request['path'], 'arguments': {}, 'artifacts': []}
        self.journal({'stage': 'received', 'observed_at': now(), 'request': normalized,
                      'content_sha256': hashlib.sha256(content).hexdigest(), 'content_bytes': len(content)})
        try:
            result = guard.boundary_for().execute_repository(
                lambda target: target.create_bytes(content) if action == 'create' else target.write_bytes(content),
                execution_request=normalized, operation=action, raise_on_block=False)
            evaluation = result['evaluation']
            outcome, error = ('executed' if result['executed'] else 'blocked'), None
        except Exception as exc:
            evaluation = getattr(exc, 'evaluation', {})
            outcome, error = 'failed', type(exc).__name__  # Never echo exception values/credentials.
        attestation = evaluation.get('execution_attestation')
        preservation = evaluation.get('cloud_preservation')
        report = evaluation.get('cloud_runtime_attestation')
        if preservation and preservation.get('ok'):
            self.last_preservation[action] = {'observed_at': now(), 'run_id': evaluation.get('run_id'),
                                               'package_id': preservation.get('package_id')}
        response = {'outcome': outcome, 'error_class': error, 'request_id': normalized['request_id'],
                    'run_id': evaluation.get('run_id'), 'authorization_status': evaluation.get('status', 'unknown'),
                    'mutation_status': (attestation or {}).get('mutation_status', 'unknown'),
                    'execution_attestation': attestation, 'decision_preservation': preservation,
                    'terminal_report_submission': report, 'automatic_retry': False,
                    'local_mutation_proof': 'operator must independently inspect source bytes',
                    'observed_at': now()}
        self.journal({'stage': 'completed', 'result': response})
        return response
