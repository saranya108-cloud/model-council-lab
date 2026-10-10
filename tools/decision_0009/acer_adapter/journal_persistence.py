"""Single JPS physical writer for the bounded trusted-host D fixture.

Every path is bootstrap-selected beneath the four authorized roots. The
Controller protocol contains no path, descriptor, truncate, or fault command.
Barriers prove fsync completion on this host, not power-loss durability.
"""

import fcntl
import hashlib
import os
from pathlib import Path
import stat
import struct

from .local_ipc import MAX_MESSAGE, ProtocolError, canonical, decode

REPOSITORY = Path('/Users/aclab/aclab/model-council-lab')
ARTIFACT_ROOT = REPOSITORY / 'logs/u04-checkpoint-d-local-proof-v1'
LIMITS = {'journal': 1024**3, 'witness': 256 * 1024**2,
          'faults': 1024**3, 'evidence': 1024**3}
CASE_JOURNAL_LIMIT = 16 * 1024**2
CASE_WITNESS_LIMIT = 4 * 1024**2
OBJECT_LIMIT = 8 * 1024**2


class PersistenceError(RuntimeError):
    pass


def identity(st):
    return (st.st_dev, st.st_ino, stat.S_IFMT(st.st_mode))


def _regular(st):
    if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
        raise PersistenceError('unaliased regular file required')


def _open_directory(path):
    """Reopen every component below the approved repository without following."""
    relative = Path(path).relative_to(REPOSITORY)
    if '..' in relative.parts:
        raise PersistenceError('descriptor-relative approved directory required')
    fd = os.open(REPOSITORY, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for component in relative.parts:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def check_budget(category, additional=0):
    if category not in LIMITS or type(additional) is not int or additional < 0:
        raise PersistenceError('closed artifact budget required')
    root = ARTIFACT_ROOT / category
    total = 0
    if root.exists():
        pinned = _open_directory(root)
        os.close(pinned)
        for directory, subdirs, files in os.walk(root, followlinks=False):
            for name in subdirs + files:
                p = Path(directory) / name
                st = p.lstat()
                if stat.S_ISLNK(st.st_mode):
                    # F10 substitution fixtures are retained; never follow them.
                    total += st.st_size
                elif stat.S_ISREG(st.st_mode):
                    total += st.st_size
                elif not stat.S_ISDIR(st.st_mode):
                    raise PersistenceError('unexpected artifact type')
    if total + additional >= LIMITS[category]:
        raise PersistenceError('cumulative artifact limit reached')
    return total


def create_directory(path):
    """Create only missing authorized directories, with directory barriers."""
    path = Path(path)
    try:
        relative = path.relative_to(ARTIFACT_ROOT)
    except ValueError as exc:
        raise PersistenceError('outside authorized artifact roots') from exc
    if not relative.parts or relative.parts[0] not in LIMITS or '..' in relative.parts:
        raise PersistenceError('outside authorized artifact roots')
    # Walk from the repository without following any path component.
    fd = os.open(REPOSITORY, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for component in path.relative_to(REPOSITORY).parts:
            try:
                child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            except FileNotFoundError:
                os.mkdir(component, dir_fd=fd)
                os.fsync(fd)
                child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.fsync(child)
            os.close(fd)
            fd = child
    finally:
        os.close(fd)


def preserve_file(path, raw):
    """Exclusive bounded evidence/fault write; never overwrites retained bytes."""
    path = Path(path)
    category = path.relative_to(ARTIFACT_ROOT).parts[0]
    check_budget(category, len(raw))
    create_directory(path.parent)
    rootfd = _open_directory(path.parent)
    try:
        fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=rootfd)
        try:
            _write_all(fd, raw)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(rootfd)
    finally:
        os.close(rootfd)


def _write_all(fd, raw):
    position = 0
    while position < len(raw):
        written = os.write(fd, raw[position:])
        if written <= 0:
            raise PersistenceError('incomplete physical write')
        position += written


def encode_frame(frame):
    raw = canonical(frame)
    if len(raw) > MAX_MESSAGE - 4096:
        raise PersistenceError('frame wire limit')
    return struct.pack('!I', len(raw)) + raw


def scan_frames(raw):
    frames, boundaries, offset = [], [0], 0
    while offset < len(raw):
        if len(raw) - offset < 4:
            return frames, boundaries, raw[offset:]
        length, = struct.unpack('!I', raw[offset:offset + 4])
        if not 0 < length <= MAX_MESSAGE:
            raise PersistenceError('invalid frame length')
        end = offset + 4 + length
        if end > len(raw):
            return frames, boundaries, raw[offset:]
        try:
            frames.append(decode(raw[offset + 4:end]))
        except ProtocolError as exc:
            raise PersistenceError('invalid retained canonical frame') from exc
        offset = end
        boundaries.append(offset)
    return frames, boundaries, b''


class JournalPersistence:
    """JPS-only writer. Its root is pinned once by trusted bootstrap."""

    def __init__(self, root, expected_root_identity, *, fault_case=False):
        self.root = Path(root)
        category = self.root.relative_to(ARTIFACT_ROOT).parts[0]
        if category != ('faults' if fault_case else 'journal'):
            raise PersistenceError('exact normal/fault journal root required')
        self.category = category
        self.fault_case = fault_case
        self._rootfd = _open_directory(self.root)
        try:
            self._root_identity = identity(os.fstat(self._rootfd))
            if list(self._root_identity) != expected_root_identity:
                raise PersistenceError('bootstrap root identity changed')
            self._fd = os.open('journal.frames', os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                               0o600, dir_fd=self._rootfd)
            try:
                _regular(os.fstat(self._fd))
                self._identity = identity(os.fstat(self._fd))
                fcntl.flock(self._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                os.fsync(self._fd)
                os.fsync(self._rootfd)
            except BaseException:
                os.close(self._fd)
                raise
        except BaseException:
            os.close(self._rootfd)
            raise
        self._barrier_length = 0
        self._pending_revision = None
        self._prefix_length = None
        self._fault_sequence = 0

    def __reduce__(self):
        raise TypeError('physical writer is not serializable')

    def _check_identity(self):
        current = _open_directory(self.root)
        try:
            if identity(os.fstat(current)) != self._root_identity:
                raise PersistenceError('root identity changed')
        finally:
            os.close(current)
        if identity(os.fstat(self._rootfd)) != self._root_identity:
            raise PersistenceError('retained root identity changed')
        st = os.stat('journal.frames', dir_fd=self._rootfd, follow_symlinks=False)
        _regular(st)
        _regular(os.fstat(self._fd))
        if identity(st) != self._identity or identity(os.fstat(self._fd)) != self._identity:
            raise PersistenceError('journal writer identity changed')

    def read(self):
        self._check_identity()
        # A fresh read-only open is separate from the writer and its buffers.
        fd = os.open('journal.frames', os.O_RDONLY | os.O_NOFOLLOW, dir_fd=self._rootfd)
        try:
            st = os.fstat(fd)
            _regular(st)
            if identity(st) != self._identity or st.st_size > CASE_JOURNAL_LIMIT:
                raise PersistenceError('readback identity/length conflict')
            raw = os.pread(fd, st.st_size + 1, 0)
            if len(raw) != st.st_size or os.fstat(fd).st_size != st.st_size:
                raise PersistenceError('readback length changed')
        finally:
            os.close(fd)
        self._check_identity()
        frames, boundaries, tail = scan_frames(raw)
        return dict(records=frames, frames=len(frames), boundaries=boundaries,
                    tail_hex=tail.hex(), bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(),
                    file_identity=list(self._identity), root_identity=list(self._root_identity),
                    barrier=self._barrier_length == len(raw), barrier_length=self._barrier_length)

    def write_frame(self, frame):
        before = self.read()
        if before['tail_hex'] or self._pending_revision is not None:
            raise PersistenceError('unresolved physical frame')
        if type(frame.get('revision')) is not int or frame['revision'] != before['frames'] + 1:
            raise PersistenceError('physical revision mismatch')
        raw = encode_frame(frame)
        case_bytes = sum(p.lstat().st_size for p in self.root.iterdir()
                         if p.is_file() and not p.is_symlink())
        if case_bytes + len(raw) >= CASE_JOURNAL_LIMIT:
            raise PersistenceError('per-case journal limit reached')
        check_budget(self.category, len(raw))
        self._check_identity()
        os.lseek(self._fd, 0, os.SEEK_END)
        if self._prefix_length is not None:
            if not self.fault_case or not 0 < self._prefix_length < len(raw):
                raise PersistenceError('enumerated partial-frame prefix required')
            raw = raw[:self._prefix_length]
            self._prefix_length = None
        _write_all(self._fd, raw)
        self._pending_revision = frame['revision']
        return dict(written=len(raw), revision=frame['revision'])

    def barrier(self, revision):
        if revision != self._pending_revision:
            raise PersistenceError('exact pending barrier required')
        self._check_identity()
        os.fsync(self._fd)
        os.fsync(self._rootfd)
        self._barrier_length = os.fstat(self._fd).st_size
        observed = self.read()
        if observed['tail_hex'] or observed['frames'] != revision:
            raise PersistenceError('incomplete frame after barrier')
        self._pending_revision = None
        return observed

    def complete_persistence(self, frame):
        """Exact completed W transaction bookkeeping; never changes JS bytes."""
        observed = self.read()
        if (observed['tail_hex'] or not observed['barrier'] or
                not 1 <= frame['revision'] <= observed['frames'] or
                observed['records'][frame['revision'] - 1] != frame or
                self._pending_revision not in (None, frame['revision'])):
            raise PersistenceError('exact completed persistence transaction required')
        self._pending_revision = None
        return {'completed': True, 'transaction': frame['transaction_id']}

    def fault_prefix(self, length):
        if not self.fault_case or type(length) is not int or length != 7:
            raise PersistenceError('F07 restricted to enumerated fault journal')
        self._prefix_length = length
        return {'armed': True}

    def fault_rewrite(self, *, length=None, frame=None):
        if not self.fault_case or (length is None) == (frame is None):
            raise PersistenceError('F08/F09 restricted fault journal operation')
        self._check_identity()
        before = self.read()
        preimage = os.pread(self._fd, before['bytes'], 0)
        if length is not None:
            if type(length) is not int or length not in before['boundaries'][:-1]:
                raise PersistenceError('enumerated earlier complete boundary required')
            postimage = preimage[:length]
        else:
            if (not before['records'] or
                    frame != dict(before['records'][-1], predecessor_hash='f' * 64)):
                raise PersistenceError('enumerated last-frame conflict required')
            postimage = preimage[:before['boundaries'][-2]] + encode_frame(frame)
        self._fault_sequence += 1
        preserve_file(self.root / ('fault-%d-preimage' % self._fault_sequence), preimage)
        preserve_file(self.root / ('fault-%d-postimage' % self._fault_sequence), postimage)
        check_budget('faults', max(0, len(postimage) - len(preimage)))
        os.ftruncate(self._fd, 0)  # Only the explicit F08/F09 fault journal.
        os.lseek(self._fd, 0, os.SEEK_SET)
        _write_all(self._fd, postimage)
        os.fsync(self._fd)
        os.fsync(self._rootfd)
        self._pending_revision = None
        self._barrier_length = len(postimage)
        return dict(preimage_sha256=hashlib.sha256(preimage).hexdigest(),
                    postimage_sha256=hashlib.sha256(postimage).hexdigest())

    def close(self):
        os.close(self._fd)
        os.close(self._rootfd)
