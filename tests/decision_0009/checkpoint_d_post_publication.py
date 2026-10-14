"""Post-publication verification for the sealed Checkpoint D candidate.

V5 in checkpoint_d_evidence.py remains the capture-time / pre-publication
verifier and is not used or modified here. This module checks the published
commit against the sealed evidence. It does not grant council acceptance or
checkpoint closure, and it does not rewrite sealed evidence or Git state.
"""

import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import unittest
import zipfile

import checkpoint_d_evidence as evidence
from tools.decision_0009.acer_adapter.journal_persistence import LIMITS
from tools.decision_0009.acer_adapter.process_services import PINNED_PYTHON, PINNED_SHA256

AUTHORIZED_PUBLICATION = '005f982dd1c234079f40877fda00e596f7fcdbf4'
AUTHORIZED_BASELINE = evidence.BASELINE
_ARTIFACT_RELATIVE = evidence.CANDIDATE.parent.parent.relative_to(evidence.REPOSITORY).as_posix()
_MAX_BYTES = 256 * 1024 ** 2
_GIT_ENV = {
    'PATH': '/usr/bin:/bin',
    'LANG': 'C',
    'LC_ALL': 'C',
    'GIT_OPTIONAL_LOCKS': '0',
    'GIT_CONFIG_NOSYSTEM': '1',
    'GIT_CONFIG_GLOBAL': '/dev/null',
    'GIT_PAGER': 'cat',
    'GIT_TERMINAL_PROMPT': '0',
}
_FULL_HASH = re.compile(r'[0-9a-f]{40}\Z')


class PublicationVerificationError(AssertionError):
    def __init__(self, code, message):
        self.code = code
        super().__init__('%s: %s' % (code, message))


def _fail(code, message):
    raise PublicationVerificationError(code, message)


def _run_git(repository, args):
    return subprocess.run(
        ['/usr/bin/git', '-C', str(repository), '--no-optional-locks', *args],
        env=_GIT_ENV, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, check=False)


def _git(repository, args, code):
    result = _run_git(repository, args)
    if result.returncode != 0:
        _fail(code, 'read-only Git check failed')
    return result.stdout


def _exact_commit(repository, revision, role):
    if not isinstance(revision, str) or _FULL_HASH.fullmatch(revision) is None:
        _fail('publication-binding', '%s must be the exact full commit hash' % role)
    result = _run_git(repository, ['rev-parse', '--verify', '--end-of-options', revision + '^{commit}'])
    if result.returncode != 0:
        _fail('publication-binding', '%s commit is unavailable' % role)
    resolved = result.stdout.decode().strip()
    if resolved != revision:
        _fail('publication-binding', '%s resolved to a different commit' % role)
    return resolved


def _head(repository):
    result = _run_git(repository, ['rev-parse', '--verify', '--end-of-options', 'HEAD'])
    if result.returncode != 0:
        _fail('publication-binding', 'HEAD is unavailable for the diagnostic record')
    return result.stdout.decode().strip()


def _is_ancestor(repository, ancestor, descendant):
    result = _run_git(repository, ['merge-base', '--is-ancestor', ancestor, descendant])
    if result.returncode == 0:
        return True
    if result.returncode == 1:
        return False
    _fail('publication-binding', 'read-only ancestry check failed')


def _name_status(repository, baseline, publication):
    raw = _git(repository, ['diff-tree', '-r', '-z', '--no-renames', '--name-status', baseline, publication],
               'change-scope')
    parts = raw.split(b'\0')
    rows = []
    index = 0
    while index + 1 < len(parts):
        status, path = parts[index], parts[index + 1]
        index += 2
        if status or path:
            rows.append(status.decode() + '\t' + path.decode())
    return rows


def _tree_entries(repository, commit, code):
    raw = _git(repository, ['ls-tree', '-r', '-z', '--full-tree', commit], code)
    entries = []
    for item in raw.split(b'\0'):
        if not item:
            continue
        meta, path = item.split(b'\t', 1)
        mode, kind, sha = meta.decode().split(' ')
        entries.append((path.decode(), mode, kind, sha))
    return entries


def _cat_batch(repository, names, code):
    payload = ''.join(name + '\n' for name in names).encode()
    result = subprocess.run(
        ['/usr/bin/git', '-C', str(repository), '--no-optional-locks', 'cat-file', '--batch'],
        input=payload, env=_GIT_ENV, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if result.returncode != 0:
        _fail(code, 'read-only Git object read failed')
    data = result.stdout
    blobs, pos = [], 0
    for _name in names:
        line_end = data.index(b'\n', pos)
        header = data[pos:line_end].decode()
        pos = line_end + 1
        if header.endswith(' missing'):
            blobs.append(None)
            continue
        size = int(header.split()[2])
        blobs.append(data[pos:pos + size])
        pos += size + 1
    return blobs


def _commit_files(repository, commit, code):
    entries = _tree_entries(repository, commit, code)
    blobs = _cat_batch(repository, [sha for _path, _mode, _kind, sha in entries], code)
    files = {}
    for (path, mode, kind, _sha), blob in zip(entries, blobs):
        if kind != 'blob' or mode != '100644' or blob is None:
            _fail(code, 'unexpected publication tree entry: %s' % path)
        files[path] = blob
    return files


def _closed_relative(relative, code):
    path = Path(relative)
    if path.is_absolute() or not path.parts or '..' in path.parts:
        _fail(code, 'closed relative path required')
    return path


def _parent(root, relative, code):
    path = _closed_relative(relative, code)
    try:
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError:
        _fail(code, 'readable directory required')
    try:
        for component in path.parts[:-1]:
            try:
                child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            except OSError:
                _fail(code, 'missing path: %s' % path.as_posix())
            os.close(fd)
            fd = child
        return fd, path.name
    except BaseException:
        os.close(fd)
        raise


def _read_relative(root, relative, code):
    parent, name = _parent(root, relative, code)
    try:
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
        except OSError:
            _fail(code, 'missing regular file: %s' % relative)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                _fail(code, 'regular file required: %s' % relative)
            if info.st_size > _MAX_BYTES:
                _fail(code, 'bounded evidence read required')
            chunks, remaining = [], info.st_size
            while remaining:
                block = os.read(fd, min(1024 ** 2, remaining))
                if not block:
                    _fail(code, 'short evidence read')
                chunks.append(block)
                remaining -= len(block)
            return b''.join(chunks)
        finally:
            os.close(fd)
    finally:
        os.close(parent)


def _load_json(root, relative, code):
    try:
        return json.loads(_read_relative(root, relative, code))
    except json.JSONDecodeError:
        _fail(code, 'malformed JSON: %s' % relative)


def _durable(root, relative, code):
    """Content identity plus capture-time metadata for diagnostics."""
    parent, name = _parent(root, relative, code)
    try:
        try:
            info = os.stat(name, dir_fd=parent, follow_symlinks=False)
        except OSError:
            _fail(code, 'missing path: %s' % relative)
        if stat.S_ISLNK(info.st_mode):
            raw, kind = os.readlink(name, dir_fd=parent).encode(), 'SYMLINK_RECEIPT'
        elif stat.S_ISREG(info.st_mode):
            try:
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
            except OSError:
                _fail(code, 'unreadable retained file: %s' % relative)
            try:
                if info.st_size > _MAX_BYTES:
                    _fail(code, 'bounded evidence read required')
                chunks, remaining = [], info.st_size
                while remaining:
                    block = os.read(fd, min(1024 ** 2, remaining))
                    if not block:
                        _fail(code, 'short evidence read')
                    chunks.append(block)
                    remaining -= len(block)
                raw, kind = b''.join(chunks), 'REGULAR'
            finally:
                os.close(fd)
        else:
            return {'kind': 'UNEXPECTED', 'bytes': info.st_size, 'sha256': None,
                    'identity': [info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode)],
                    'mtime_ns': info.st_mtime_ns, 'nlink': info.st_nlink}
        return {'kind': kind, 'bytes': len(raw), 'sha256': evidence._sha(raw),
                'identity': [info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode)],
                'mtime_ns': info.st_mtime_ns, 'nlink': info.st_nlink}
    finally:
        os.close(parent)


def _walk(root, top, code, *, exclude=None):
    result = {}
    if not top.exists():
        return result
    for directory, subdirs, files in os.walk(top, followlinks=False):
        subdirs.sort()
        files.sort()
        for name in list(subdirs):
            path = Path(directory) / name
            if exclude is not None and path == exclude:
                subdirs.remove(name)
            elif path.is_symlink():
                relative = path.relative_to(root).as_posix()
                result[relative] = _durable(root, relative, code)
                subdirs.remove(name)
        for name in files:
            path = Path(directory) / name
            relative = path.relative_to(root).as_posix()
            result[relative] = _durable(root, relative, code)
    return result


class _Volatile:
    def __init__(self):
        self.compared = 0
        self.differing = 0

    def observe(self, expected, live):
        self.compared += 1
        if (expected.get('identity') != live['identity'] or expected.get('mtime_ns') != live['mtime_ns']
                or expected.get('nlink') != live['nlink']):
            self.differing += 1


def _match_durable(expected, live, code, label):
        if live['kind'] == 'UNEXPECTED' or live['kind'] != expected.get('kind'):
            _fail(code, 'kind differs: %s' % label)
        if live['bytes'] != expected.get('bytes') or live['sha256'] != expected.get('sha256'):
            _fail(code, 'bytes or digest differ: %s' % label)


def _bind_commits(repository, publication, baseline, enforce_authorized_identifiers):
    publication = _exact_commit(repository, publication, 'publication')
    baseline = _exact_commit(repository, baseline, 'baseline')
    if enforce_authorized_identifiers and (publication != AUTHORIZED_PUBLICATION or baseline != AUTHORIZED_BASELINE):
        _fail('publication-binding',
              'verification is bound to the published Checkpoint D commit and the Checkpoint C baseline')
    if publication == baseline or not _is_ancestor(repository, baseline, publication):
        _fail('publication-binding', 'Checkpoint C baseline is not an ancestor of the publication commit')
    # HEAD is diagnostic only. The commit under verification stays `publication`.
    return publication, baseline, _head(repository)


def _check_manifest(source, scope, baseline):
    modified, added = source.get('modified'), source.get('new')
    if modified != scope.get('modified') or added != scope.get('new'):
        _fail('manifest', 'sealed manifest scope lists disagree with the sealed authority scope')
    if len(modified) != 4 or len(added) != 6:
        _fail('change-scope', 'sealed scope is not the declared four modified and six added paths')
    if evidence._sha(evidence._json(source['files'])) != source.get('snapshot_sha256'):
        _fail('manifest', 'source snapshot hash does not match the sealed file map')
    if evidence._sha(evidence._json(evidence.SCOPE)) != source.get('scope_sha256'):
        _fail('manifest', 'scope hash does not match the sealed scope record')
    if source.get('baseline_head') != baseline:
        _fail('publication-binding', 'manifest baseline does not match the Checkpoint C baseline')
    for key, expected in (('branch', evidence.BRANCH), ('accepted_c_snapshot', evidence.ACCEPTED_C),
                          ('platform', 'macOS arm64'), ('python_version', '3.14.7')):
        if source.get(key) != expected:
            _fail('manifest', 'sealed source manifest field differs: ' + key)
    if source.get('interpreter') != str(PINNED_PYTHON) or source.get('interpreter_sha256') != PINNED_SHA256:
        _fail('manifest', 'sealed interpreter binding differs')
    identities = source.get('source_identities')
    if set(identities) != set(source['files']):
        _fail('manifest', 'source identity paths disagree with the sealed file map')
    for path, digest in source['files'].items():
        identity = identities[path]
        if identity.get('kind') != 'REGULAR' or identity.get('sha256') != digest:
            _fail('manifest', 'source identity does not match the sealed file digest: ' + path)
    git_scope = source.get('git_scope') or {}
    if sorted(git_scope.get('diff', [])) != sorted('M\t' + path for path in modified):
        _fail('manifest', 'sealed capture-time diff record disagrees with the manifest')
    if sorted(git_scope.get('status', [])) != sorted([' M ' + path for path in modified] + ['?? ' + path for path in added]):
        _fail('manifest', 'sealed capture-time status record disagrees with the manifest')
    if git_scope.get('staged') != []:
        _fail('manifest', 'sealed capture-time staged record is not empty')
    baseline_files = source.get('baseline_files')
    if set(baseline_files) != set(source['files']) - set(added):
        _fail('manifest', 'baseline file set is not the sealed source set without the added paths')
    modified_set = set(modified)
    if any(path not in baseline_files for path in modified):
        _fail('manifest', 'modified path missing from sealed baseline files')
    if any(source['files'][path] == baseline_files[path] for path in modified):
        _fail('manifest', 'a declared modification is identical to its sealed baseline')
    if any(source['files'][path] != baseline_files[path] for path in baseline_files if path not in modified_set):
        _fail('manifest', 'a path outside the declared modifications differs from its sealed baseline')
    return modified, added


def _check_scope(repository, baseline, publication, modified, added):
    actual = _name_status(repository, baseline, publication)
    expected = ['M\t' + path for path in modified] + ['A\t' + path for path in added]
    if sorted(actual) != sorted(expected):
        _fail('change-scope', 'baseline-to-publication diff is not the sealed manifest scope')


def _check_committed_source(repository, publication, source):
    files = _commit_files(repository, publication, 'committed-source')
    hashes = {path: evidence._sha(blob) for path, blob in files.items()}
    if hashes != source['files']:
        _fail('committed-source', 'publication blobs do not match the sealed source manifest')
    for path, blob in files.items():
        if source['source_identities'][path].get('bytes') != len(blob):
            _fail('committed-source', 'publication blob length does not match the sealed source identity: ' + path)


def _check_baseline_source(repository, baseline, source):
    names = sorted(source['baseline_files'])
    blobs = _cat_batch(repository, [baseline + ':' + path for path in names], 'baseline-source')
    for path, blob in zip(names, blobs):
        if blob is None or evidence._sha(blob) != source['baseline_files'][path]:
            _fail('baseline-source', 'baseline blob does not match the sealed baseline digest: ' + path)


def _check_archived_source(candidate, source):
    for path, digest in source['files'].items():
        archived = str(Path('source') / path)
        if evidence._sha(_read_relative(candidate, archived, 'sealed-source')) != digest:
            _fail('sealed-source', 'archived source does not match the sealed manifest: ' + path)


def _check_seal(candidate, source):
    seal = _load_json(candidate, 'seal.json', 'sealed-package')
    if (seal.get('schema') != 'decision-0009-checkpoint-d-seal/v1' or seal.get('status') != 'REVIEW_CANDIDATE'
            or seal.get('source_snapshot') != source['snapshot_sha256']):
        _fail('sealed-package', 'seal source or status differs')
    recorded = seal.get('files')
    if not isinstance(recorded, dict):
        _fail('sealed-package', 'seal file map differs')
    for name in recorded:
        _closed_relative(name, 'sealed-package')
    digest_map = {path: entry['sha256'] for path, entry in recorded.items()}
    if evidence._sha(evidence._json(digest_map)) != seal.get('package_content_sha256'):
        _fail('sealed-package', 'package-content hash differs')
    for path, entry in recorded.items():
        raw = _read_relative(candidate, path, 'sealed-package')
        if len(raw) != entry.get('bytes') or evidence._sha(raw) != entry.get('sha256'):
            _fail('sealed-package', 'sealed package bytes differ: ' + path)
    present = set(_walk(candidate, candidate, 'sealed-package'))
    extras = sorted(present - set(recorded) - {'seal.json'})
    return seal, extras


def _check_retained(repository, candidate, volatile):
    retained = _load_json(candidate, 'retained-artifacts-after.json', 'retained-artifact')
    if not isinstance(retained, dict):
        _fail('retained-artifact', 'retained artifact record differs')
    artifact_root = repository / _ARTIFACT_RELATIVE
    live = {}
    for category in LIMITS:
        live.update(_walk(repository, artifact_root / category, 'retained-artifact', exclude=candidate))
    for path, expected in retained.items():
        if path not in live:
            _fail('retained-artifact', 'sealed retained artifact is missing: ' + path)
        _match_durable(expected, live[path], 'retained-artifact', path)
        volatile.observe(expected, live[path])
    additions = sorted(set(live) - set(retained))
    return retained, additions


def _prior_membership(entries, name):
    prefix = Path('logs') / name
    hashes = {str(Path(path).relative_to(prefix)): entry['sha256'] for path, entry in entries.items()}
    return evidence._sha(evidence._json(hashes)), hashes


def _check_prior(repository, sealed, volatile, enforce_constants):
    if not isinstance(sealed, dict):
        _fail('sealed-evidence', 'prior evidence record differs')
    for name, block in sealed.items():
        _closed_relative('logs/' + name, 'sealed-evidence')
        live = _walk(repository, repository / 'logs' / name, 'sealed-evidence')
        for path, entry in live.items():
            if entry['kind'] == 'UNEXPECTED':
                _fail('sealed-evidence', 'prior evidence type differs: ' + path)
        membership, _hashes = _prior_membership(live, name)
        if membership != block.get('membership_sha256') or set(live) != set(block.get('files', {})):
            _fail('sealed-evidence', 'prior evidence membership differs: ' + name)
        for path, expected in block['files'].items():
            _match_durable(expected, live[path], 'sealed-evidence', path)
            volatile.observe(expected, live[path])
        if enforce_constants:
            count, expected_hash = evidence.PRIOR[name]
            if len(live) != count or membership != expected_hash:
                _fail('sealed-evidence', 'prior A/B/C membership differs: ' + name)
    if enforce_constants:
        if set(sealed) != set(evidence.PRIOR):
            _fail('sealed-evidence', 'prior A/B/C membership differs')
        for name, expected in evidence.PRIOR_SEALS.items():
            if evidence._sha(_read_relative(repository, 'logs/' + name, 'sealed-evidence')) != expected:
                _fail('sealed-evidence', 'accepted seal differs')
        accepted = _load_json(
            repository,
            'logs/u04-checkpoint-c-20261007/candidate-08-sol-final-corrective/source-manifest.json',
            'sealed-evidence')
        if accepted.get('snapshot_sha256') != evidence.ACCEPTED_C:
            _fail('sealed-evidence', 'accepted C source binding differs')


def _check_case_evidence(candidate, source):
    scope = _load_json(candidate, 'authority-scope.json', 'sealed-evidence')
    if scope != evidence.SCOPE:
        _fail('sealed-evidence', 'authorization scope differs')
    retained = _load_json(candidate, 'retained-artifacts-after.json', 'sealed-evidence')
    historical = _load_json(candidate, 'historical-development-before.json', 'sealed-evidence')
    if not all(retained.get(path) == entry for path, entry in historical.get('files', {}).items()):
        _fail('sealed-evidence', 'historical evidence changed')
    members = _load_json(candidate, 'artifact-membership.json', 'sealed-evidence')
    if not all(retained.get(path) == entry for path, entry in members.items()):
        _fail('sealed-evidence', 'final original artifacts changed')
    reports, validation = [], {}
    identities = {}
    for name in evidence.PATTERNS:
        result = _load_json(candidate, 'validation/' + name + '.json', 'sealed-evidence')
        raw = _read_relative(candidate, 'validation/' + name + '.log', 'sealed-evidence').decode()
        if not (result['source_snapshot'] == source['snapshot_sha256'] and result['complete']
                and result['tests'] == result['planned_tests'] == len(result['started']) == len(result['finished'])
                and not any(result[key] for key in (
                    'failures', 'errors', 'skips', 'expected_failures', 'unexpected_successes'))
                and result['exit_state']['equivalent_unittest_exit_status'] == 0):
            _fail('sealed-evidence', 'suite closure incomplete')
        if not (re.search(r'Ran %d tests? in ' % result['tests'], raw) and raw.rstrip().endswith('OK')):
            _fail('sealed-evidence', 'raw suite result differs')
        if not (result['subcase_count'] == len(result['subcases'])
                and all(item['outcome'] == 'PASS' for item in result['subcases'])):
            _fail('sealed-evidence', 'subcase closure differs')
        for test in result['test_identities']:
            if source['files'][test['source']] != test['sha256']:
                _fail('sealed-evidence', 'test source identity differs')
        identities[name] = {test['id'] for test in result['test_identities']}
        if not (set(result['started']) == set(result['finished']) == identities[name]):
            _fail('sealed-evidence', 'test identity membership differs')
        reports.extend(result['cases'])
        validation[name] = {key: result[key] for key in
                            ('tests', 'subcase_count', 'failures', 'errors', 'skips', 'exit_state')}
    if not (identities['focused'] < identities['adapter'] and not identities['startup'] & identities['adapter']):
        _fail('sealed-evidence', 'suite population differs')
    if len({report['case_id'] for report in reports}) != len(reports):
        _fail('sealed-evidence', 'final case reused')
    archive_bytes = _read_relative(candidate, 'artifacts.zip', 'sealed-evidence')
    with zipfile.ZipFile(io.BytesIO(archive_bytes), 'r') as archive:
        names = archive.namelist()
        regular = {path for path, entry in members.items() if entry['kind'] == 'REGULAR'}
        if len(names) != len(set(names)) or set(names) != regular:
            _fail('sealed-evidence', 'archive membership differs')
        for path in names:
            if evidence._relative(path) != path or archive.getinfo(path).compress_type != zipfile.ZIP_STORED:
                _fail('sealed-evidence', 'archive path or type differs')
            raw = archive.read(path)
            if len(raw) != members[path]['bytes'] or evidence._sha(raw) != members[path]['sha256']:
                _fail('sealed-evidence', 'archived artifact bytes differ')
        audits = []
        for report in reports:
            path = evidence._relative(report['artifact_roots']['evidence']) + '/process-observations.json'
            if json.loads(archive.read(path)) != report:
                _fail('sealed-evidence', 'case report changed after closure')
            audits.append(evidence._audit_case(report, archive.read, set(names)))
        if evidence._enrollments(reports, archive.read) != _load_json(candidate, 'enrollment-manifest.json', 'sealed-evidence'):
            _fail('sealed-evidence', 'exact enrollment binding differs')
    if audits != _load_json(candidate, 'independent-closure.json', 'sealed-evidence'):
        _fail('sealed-evidence', 'independent closure differs')
    if evidence._coverage(reports) != _load_json(candidate, 'fault-coverage.json', 'sealed-evidence'):
        _fail('sealed-evidence', 'fault coverage differs')
    closure = _load_json(candidate, 'closure.json', 'sealed-evidence')
    if not (closure['source_snapshot'] == source['snapshot_sha256']
            and closure['status'] == 'IMPLEMENTATION_VALIDATION_COMPLETE_REVIEW_PENDING'
            and closure['cases'] == len(reports)
            and closure['owned_children_reaped'] == sum(item['owned_children'] for item in audits)
            and closure['actual_controller_sigkills'] == sum(item['actual_controller_sigkills'] for item in audits)
            and closure['peak_processes'] == max(item['peak_processes'] for item in audits)
            and closure['validation'] == validation):
        _fail('sealed-evidence', 'final closure differs')
    return closure


def verify_checkpoint_d_publication(repository, candidate, publication, baseline, *,
                                    enforce_authorized_identifiers=False):
    """Verify one publication commit against a sealed Checkpoint D candidate.

    `publication` is the commit under test. Current HEAD is recorded and is
    never substituted for it. Volatile filesystem identity is diagnostic.
    """
    repository = Path(repository)
    candidate = Path(candidate)
    if not repository.is_absolute():
        repository = repository.absolute()
    if not candidate.is_absolute():
        candidate = candidate.absolute()
    publication, baseline, head = _bind_commits(
        repository, publication, baseline, enforce_authorized_identifiers)
    source = _load_json(candidate, 'source-manifest.json', 'manifest')
    scope = _load_json(candidate, 'authority-scope.json', 'manifest')
    modified, added = _check_manifest(source, scope, baseline)
    _check_scope(repository, baseline, publication, modified, added)
    _check_committed_source(repository, publication, source)
    _check_baseline_source(repository, baseline, source)
    _check_archived_source(candidate, source)
    seal, package_additions = _check_seal(candidate, source)
    volatile = _Volatile()
    _retained, root_additions = _check_retained(repository, candidate, volatile)
    _check_prior(repository, _load_json(candidate, 'prior-evidence.json', 'sealed-evidence'),
                 volatile, enforce_authorized_identifiers)
    closure = _check_case_evidence(candidate, source)
    return {
        'verification': 'POST_PUBLICATION_PASS',
        'publication': publication,
        'baseline': baseline,
        'head_diagnostic': head,
        'head_matches_publication': head == publication,
        'source_snapshot': source['snapshot_sha256'],
        'package_content_sha256': seal['package_content_sha256'],
        'seal_sha256': evidence._sha(_read_relative(candidate, 'seal.json', 'sealed-package')),
        'cases': closure['cases'],
        'owned_children_reaped': closure['owned_children_reaped'],
        'declared_scope': {'modified': list(modified), 'added': list(added)},
        'committed_source_paths': len(source['files']),
        'baseline_source_paths': len(source['baseline_files']),
        'retained_sealed': len(_retained),
        'post_seal_additions': {
            'retained_roots': root_additions,
            'candidate_package': package_additions,
            'note': 'These paths are outside the sealed candidate and are not members of it.',
        },
        'volatile_metadata': {
            'compared': volatile.compared,
            'differing': volatile.differing,
            'fields': ['device', 'inode', 'mtime_ns', 'nlink'],
            'effect_on_verification': 'diagnostic-only',
        },
    }


def verify_published_checkpoint_d():
    """Verify the authorized published Checkpoint D commit against its seal.

    This does not grant council acceptance or checkpoint closure.
    """
    return verify_checkpoint_d_publication(
        evidence.REPOSITORY, evidence.CANDIDATE,
        publication=AUTHORIZED_PUBLICATION, baseline=AUTHORIZED_BASELINE,
        enforce_authorized_identifiers=True)


class _Fixture:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


def _fixture_git(repository, args, env):
    result = subprocess.run(
        ['/usr/bin/git', '-C', str(repository), '-c', 'core.autocrlf=false', *args],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.decode() or 'fixture git failed')
    return result.stdout.decode().strip()


def _write_bytes(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)


def _entry(raw, kind):
    return {'kind': kind, 'bytes': len(raw), 'sha256': evidence._sha(raw),
            'identity': [0, 0, 0], 'mtime_ns': 0, 'nlink': 1}


def build_published_fixture(root):
    """Isolated repository and candidate. Does not use the real seal as a writable fixture."""
    repository = Path(root)
    env = dict(_GIT_ENV)
    env.update(GIT_AUTHOR_NAME='Decision 0009 Fixture', GIT_AUTHOR_EMAIL='fixture@example.invalid',
               GIT_COMMITTER_NAME='Decision 0009 Fixture', GIT_COMMITTER_EMAIL='fixture@example.invalid')
    template = repository / 'git-template'
    template.mkdir()
    _fixture_git(repository, ['init', '--template', str(template), '-b', 'fixture'], env)
    unchanged = 'post-publication-fixture-unchanged.txt'
    modified, added = list(evidence.SCOPE['modified']), list(evidence.SCOPE['new'])
    for path in [unchanged, *modified]:
        _write_bytes(repository / path, b'baseline-v1\n')
    _fixture_git(repository, ['add', '--', unchanged, *modified], env)
    _fixture_git(repository, ['commit', '-m', 'baseline'], env)
    for path in modified:
        _write_bytes(repository / path, b'published-v1\n')
    for path in added:
        _write_bytes(repository / path, b'added-v1\n')
    _fixture_git(repository, ['add', '--', *modified, *added], env)
    _fixture_git(repository, ['commit', '-m', 'publication'], env)
    _write_bytes(repository / unchanged, b'later-head\n')
    _fixture_git(repository, ['add', '--', unchanged], env)
    _fixture_git(repository, ['commit', '-m', 'later'], env)
    head = _fixture_git(repository, ['rev-parse', 'HEAD'], env)
    publication = _fixture_git(repository, ['rev-parse', 'HEAD~1'], env)
    baseline = _fixture_git(repository, ['rev-parse', 'HEAD~2'], env)
    published = _commit_files(repository, publication, 'committed-source')
    baseline_blobs = _commit_files(repository, baseline, 'baseline-source')
    files = {path: evidence._sha(blob) for path, blob in published.items()}
    identities = {path: {'kind': 'REGULAR', 'bytes': len(blob), 'sha256': files[path],
                         'identity': [0, 0, 0], 'mtime_ns': 0, 'nlink': 1}
                  for path, blob in published.items()}
    manifest = {
        'files': files,
        'snapshot_sha256': evidence._sha(evidence._json(files)),
        'source_identities': identities,
        'baseline_files': {path: evidence._sha(blob) for path, blob in baseline_blobs.items()},
        'baseline_head': baseline,
        'branch': evidence.BRANCH,
        'accepted_c_snapshot': evidence.ACCEPTED_C,
        'modified': modified,
        'new': added,
        'scope_sha256': evidence._sha(evidence._json(evidence.SCOPE)),
        'interpreter': str(PINNED_PYTHON),
        'interpreter_sha256': PINNED_SHA256,
        'platform': 'macOS arm64',
        'python_version': '3.14.7',
        'git_scope': {
            'diff': ['M\t' + path for path in modified],
            'status': [' M ' + path for path in modified] + ['?? ' + path for path in added],
            'staged': [],
        },
    }
    case = 'post-publication-fixture-case'
    roots = {category: str(evidence.REPOSITORY / _ARTIFACT_RELATIVE / category / case)
             for category in ('journal', 'witness', 'faults', 'evidence')}
    real_archive = evidence.CANDIDATE / 'artifacts.zip'
    with zipfile.ZipFile(real_archive) as archive:
        bootstrap_name = next(name for name in archive.namelist() if name.endswith('/bootstrap.json'))
        bootstrap_raw = archive.read(bootstrap_name)
    bootstrap = json.loads(bootstrap_raw)
    faults = []
    cuts = list(evidence.CUTS)
    for index, name in enumerate(evidence.FAULTS):
        item = {'fault': name, 'stage': cuts[index % len(cuts)]}
        if name == 'F16':
            item['operation'] = 'RESERVE_FRAME'
        faults.append(item)
    mono = 1
    processes = []
    roles = ('CONTROLLER', 'W', 'C', 'JPS')
    environment = sorted(['D_PROOF_CHILD', 'LANG', 'LC_ALL', 'PYTHONDONTWRITEBYTECODE', 'PYTHONNOUSERSITE'])
    for index, role in enumerate(roles):
        processes.append({
            'monotonic_ns': mono, 'role': role, 'event': 'POPEN',
            'operating_processes_including_h': index + 2, 'interpreter': str(PINNED_PYTHON),
            'interpreter_sha256': PINNED_SHA256, 'environment_keys': environment, 'pass_fds': [7],
        })
        mono += 1
    for role in roles:
        processes.append({
            'monotonic_ns': mono, 'role': role, 'event': 'EXIT_REAP',
            'mechanism': 'sole-owner-waitpid-WNOHANG', 'wait_status': 0, 'returncode': 0,
        })
        mono += 1
    report = {
        'case_id': case, 'artifact_roots': roots, 'cleanup_errors': [],
        'quiescence': {'all_reaped': True, 'uncertain': False, 'owned_children': 4,
                       'peak_operating_processes_including_h': 5},
        'processes': processes, 'original_instances': bootstrap['original_instances'],
        'persistence_observations': 0, 'independent_observations': 0, 'faults': faults,
    }
    boot_rel = evidence._relative(roots['evidence'] + '/bootstrap.json')
    proc_rel = evidence._relative(roots['evidence'] + '/process-observations.json')
    proc_raw = evidence._json(report)
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w', compression=zipfile.ZIP_STORED, allowZip64=False) as archive:
        archive.writestr(boot_rel, bootstrap_raw)
        archive.writestr(proc_rel, proc_raw)
    zip_bytes = stream.getvalue()
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as archive:
        names = set(archive.namelist())
        audit = evidence._audit_case(report, archive.read, names)
        enrollment = evidence._enrollments([report], archive.read)
        coverage = evidence._coverage([report])
    link_rel = _ARTIFACT_RELATIVE + '/faults/fixture-sealed-link'
    note_rel = _ARTIFACT_RELATIVE + '/journal/sealed-note.txt'
    note_raw = b'sealed-note\n'
    link_raw = b'x'
    (repository / link_rel).parent.mkdir(parents=True, exist_ok=True)
    os.symlink('x', repository / link_rel)
    _write_bytes(repository / note_rel, note_raw)
    _write_bytes(repository / boot_rel, bootstrap_raw)
    _write_bytes(repository / proc_rel, proc_raw)
    members = {boot_rel: _entry(bootstrap_raw, 'REGULAR'), proc_rel: _entry(proc_raw, 'REGULAR'),
               link_rel: _entry(link_raw, 'SYMLINK_RECEIPT')}
    retained = dict(members)
    retained[note_rel] = _entry(note_raw, 'REGULAR')
    source_path = 'tests/decision_0009/test_acer_adapter_process.py'
    focused_id, adapter_id, startup_id = ('fixture.Focused.test_kept', 'fixture.Adapter.test_extra',
                                           'fixture.Startup.test_other')
    suites = {
        'focused': ([focused_id], [report], 'Ran 1 test in 0.001s\n\nOK\n'),
        'adapter': ([focused_id, adapter_id], [], 'Ran 2 tests in 0.001s\n\nOK\n'),
        'startup': ([startup_id], [], 'Ran 1 test in 0.001s\n\nOK\n'),
    }
    validation, results = {}, {}
    for name, (test_ids, cases, log) in suites.items():
        result = {
            'name': name, 'source_snapshot': manifest['snapshot_sha256'], 'complete': True,
            'tests': len(test_ids), 'planned_tests': len(test_ids), 'started': list(test_ids),
            'finished': list(test_ids), 'failures': 0, 'errors': 0, 'skips': 0,
            'expected_failures': 0, 'unexpected_successes': 0,
            'exit_state': {'equivalent_unittest_exit_status': 0},
            'subcase_count': 0, 'subcases': [], 'cases': cases,
            'test_identities': [{'id': test_id, 'source': source_path, 'sha256': files[source_path]}
                                for test_id in test_ids],
        }
        results[name] = result
        validation[name] = {key: result[key] for key in
                            ('tests', 'subcase_count', 'failures', 'errors', 'skips', 'exit_state')}
    closure = {
        'status': 'IMPLEMENTATION_VALIDATION_COMPLETE_REVIEW_PENDING',
        'source_snapshot': manifest['snapshot_sha256'], 'cases': 1,
        'owned_children_reaped': audit['owned_children'],
        'actual_controller_sigkills': audit['actual_controller_sigkills'],
        'peak_processes': audit['peak_processes'], 'validation': validation,
    }
    candidate = repository / _ARTIFACT_RELATIVE / 'evidence' / evidence.CANDIDATE.name
    for path, blob in published.items():
        _write_bytes(candidate / 'source' / path, blob)
    _write_bytes(candidate / 'source-manifest.json', evidence._json(manifest))
    _write_bytes(candidate / 'authority-scope.json', evidence._json(evidence.SCOPE))
    prior_rel = 'logs/fixture-prior/note.txt'
    prior_raw = b'prior\n'
    _write_bytes(repository / prior_rel, prior_raw)
    prior_entries = {prior_rel: _entry(prior_raw, 'REGULAR')}
    membership, _hashes = _prior_membership(prior_entries, 'fixture-prior')
    _write_bytes(candidate / 'prior-evidence.json', evidence._json({
        'fixture-prior': {'files': prior_entries, 'membership_sha256': membership}}))
    _write_bytes(candidate / 'retained-artifacts-after.json', evidence._json(retained))
    _write_bytes(candidate / 'historical-development-before.json',
                 evidence._json({'status': 'HISTORICAL_NOT_FINAL', 'files': {}}))
    _write_bytes(candidate / 'artifact-membership.json', evidence._json(members))
    _write_bytes(candidate / 'artifacts.zip', zip_bytes)
    _write_bytes(candidate / 'enrollment-manifest.json', evidence._json(enrollment))
    _write_bytes(candidate / 'independent-closure.json', evidence._json([audit]))
    _write_bytes(candidate / 'fault-coverage.json', evidence._json(coverage))
    _write_bytes(candidate / 'closure.json', evidence._json(closure))
    for name, (_ids, _cases, log) in suites.items():
        _write_bytes(candidate / 'validation' / (name + '.json'), evidence._json(results[name]))
        _write_bytes(candidate / 'validation' / (name + '.log'), log.encode())
    recorded = {}
    for path, entry in _walk(candidate, candidate, 'sealed-package').items():
        recorded[path] = {'bytes': entry['bytes'], 'sha256': entry['sha256']}
    seal = {'schema': 'decision-0009-checkpoint-d-seal/v1', 'files': recorded,
            'package_content_sha256': evidence._sha(evidence._json({path: entry['sha256'] for path, entry in recorded.items()})),
            'source_snapshot': manifest['snapshot_sha256'], 'status': 'REVIEW_CANDIDATE'}
    _write_bytes(candidate / 'seal.json', evidence._json(seal))
    _write_bytes(repository / _ARTIFACT_RELATIVE / 'evidence' / 'post-seal-unrelated.txt', b'later addition\n')
    _write_bytes(candidate / 'POST_SEAL_UNRELATED.txt', b'not part of the seal\n')
    return _Fixture(repository=repository, candidate=candidate, publication=publication, baseline=baseline,
                    head=head, note=repository / note_rel,
                    archived=candidate / 'source' / modified[0], manifest=candidate / 'source-manifest.json')


class CheckpointDPostPublicationTests(unittest.TestCase):
    def _fixture(self):
        directory = tempfile.TemporaryDirectory(dir=str(evidence.REPOSITORY / 'logs'))
        self.addCleanup(directory.cleanup)
        return build_published_fixture(directory.name)

    def _verify_fixture(self, fixture, **kwargs):
        values = dict(publication=fixture.publication, baseline=fixture.baseline,
                      enforce_authorized_identifiers=False)
        values.update(kwargs)
        return verify_checkpoint_d_publication(fixture.repository, fixture.candidate, **values)

    def test_published_checkpoint_d_passes(self):
        result = verify_published_checkpoint_d()
        self.assertEqual(result['verification'], 'POST_PUBLICATION_PASS')
        self.assertEqual(result['publication'], AUTHORIZED_PUBLICATION)
        self.assertEqual(result['baseline'], AUTHORIZED_BASELINE)
        self.assertEqual(len(result['declared_scope']['modified']), 4)
        self.assertEqual(len(result['declared_scope']['added']), 6)
        self.assertEqual(result['volatile_metadata']['effect_on_verification'], 'diagnostic-only')
        self.assertIsInstance(result['post_seal_additions']['retained_roots'], list)
        self.assertIsInstance(result['post_seal_additions']['candidate_package'], list)
        print(json.dumps(result, sort_keys=True))

    def test_wrong_publication_commit_fails(self):
        cases = (
            AUTHORIZED_BASELINE,
            'HEAD',
            AUTHORIZED_PUBLICATION[:12],
            '0' * 40,
        )
        for publication in cases:
            with self.subTest(publication=publication):
                with self.assertRaises(PublicationVerificationError) as caught:
                    verify_checkpoint_d_publication(
                        evidence.REPOSITORY, evidence.CANDIDATE,
                        publication=publication, baseline=AUTHORIZED_BASELINE,
                        enforce_authorized_identifiers=True)
                self.assertEqual(caught.exception.code, 'publication-binding')

    def test_verification_does_not_retarget_to_head(self):
        fixture = self._fixture()
        result = self._verify_fixture(fixture)
        self.assertEqual(result['verification'], 'POST_PUBLICATION_PASS')
        self.assertEqual(result['publication'], fixture.publication)
        self.assertEqual(result['head_diagnostic'], fixture.head)
        self.assertNotEqual(result['head_diagnostic'], result['publication'])
        with self.assertRaises(PublicationVerificationError) as caught:
            self._verify_fixture(fixture, publication='HEAD')
        self.assertEqual(caught.exception.code, 'publication-binding')

    def test_unexpected_change_scope_fails(self):
        fixture = self._fixture()
        with self.assertRaises(PublicationVerificationError) as caught:
            self._verify_fixture(fixture, publication=fixture.head)
        self.assertEqual(caught.exception.code, 'change-scope')

    def test_manifest_mismatch_fails(self):
        fixture = self._fixture()
        manifest = json.loads(fixture.manifest.read_text())
        manifest['snapshot_sha256'] = '0' * 64
        fixture.manifest.write_bytes(evidence._json(manifest))
        with self.assertRaises(PublicationVerificationError) as caught:
            self._verify_fixture(fixture)
        self.assertEqual(caught.exception.code, 'manifest')

    def test_baseline_mismatch_fails(self):
        fixture = self._fixture()
        manifest = json.loads(fixture.manifest.read_text())
        manifest['baseline_files'][manifest['modified'][0]] = '0' * 64
        fixture.manifest.write_bytes(evidence._json(manifest))
        with self.assertRaises(PublicationVerificationError) as caught:
            self._verify_fixture(fixture)
        self.assertEqual(caught.exception.code, 'baseline-source')

    def test_altered_sealed_source_fails(self):
        fixture = self._fixture()
        fixture.archived.write_bytes(fixture.archived.read_bytes() + b'\n')
        with self.assertRaises(PublicationVerificationError) as caught:
            self._verify_fixture(fixture)
        self.assertEqual(caught.exception.code, 'sealed-source')

    def test_missing_sealed_source_fails(self):
        fixture = self._fixture()
        fixture.archived.unlink()
        with self.assertRaises(PublicationVerificationError) as caught:
            self._verify_fixture(fixture)
        self.assertEqual(caught.exception.code, 'sealed-source')

    def test_retained_artifact_corruption_fails(self):
        fixture = self._fixture()
        fixture.note.write_bytes(b'corrupted\n')
        with self.assertRaises(PublicationVerificationError) as caught:
            self._verify_fixture(fixture)
        self.assertEqual(caught.exception.code, 'retained-artifact')

    def test_retained_artifact_missing_fails(self):
        fixture = self._fixture()
        fixture.note.unlink()
        with self.assertRaises(PublicationVerificationError) as caught:
            self._verify_fixture(fixture)
        self.assertEqual(caught.exception.code, 'retained-artifact')

    def test_post_seal_additions_are_reported_and_do_not_invalidate(self):
        fixture = self._fixture()
        result = self._verify_fixture(fixture)
        self.assertEqual(result['verification'], 'POST_PUBLICATION_PASS')
        self.assertIn(_ARTIFACT_RELATIVE + '/evidence/post-seal-unrelated.txt',
                      result['post_seal_additions']['retained_roots'])
        self.assertIn('POST_SEAL_UNRELATED.txt', result['post_seal_additions']['candidate_package'])
        self.assertGreater(result['volatile_metadata']['differing'], 0)
        self.assertNotIn('POST_SEAL_UNRELATED.txt', json.loads((fixture.candidate / 'seal.json').read_text())['files'])

    def test_verifier_does_not_alter_tracked_or_staged_state(self):
        repository = evidence.REPOSITORY

        def git_snapshot():
            def run(args):
                result = _run_git(repository, args)
                if result.returncode != 0:
                    raise AssertionError(result.stderr.decode())
                return result.stdout
            return {
                'head': run(['rev-parse', 'HEAD']),
                'staged': run(['diff', '--cached', '--name-status']),
                'status': run(['status', '--porcelain=v1', '--untracked-files=all']),
            }

        def artifact_fingerprint():
            rows = []
            top = repository / _ARTIFACT_RELATIVE
            for directory, subdirs, files in os.walk(top, followlinks=False):
                subdirs.sort()
                files.sort()
                for name in files:
                    path = Path(directory) / name
                    info = path.lstat()
                    rows.append((path.relative_to(repository).as_posix(), info.st_size, info.st_mtime_ns))
            return rows

        before_git = git_snapshot()
        before_index = hashlib.sha256((repository / '.git' / 'index').read_bytes()).hexdigest()
        before_files = artifact_fingerprint()
        before_seal = (evidence.CANDIDATE / 'seal.json').read_bytes()
        result = verify_published_checkpoint_d()
        after_index = hashlib.sha256((repository / '.git' / 'index').read_bytes()).hexdigest()
        after_seal = (evidence.CANDIDATE / 'seal.json').read_bytes()
        after_files = artifact_fingerprint()
        after_git = git_snapshot()
        self.assertEqual(result['verification'], 'POST_PUBLICATION_PASS')
        self.assertEqual(before_git, after_git)
        self.assertEqual(before_index, after_index)
        self.assertEqual(before_seal, after_seal)
        self.assertEqual(before_files, after_files)


if __name__ == '__main__':
    print(json.dumps(verify_published_checkpoint_d(), sort_keys=True))
