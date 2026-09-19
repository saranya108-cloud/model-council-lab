"""Minimal ctypes worker. Importing this module never loads a CUDA library.

run() is a worker-side entry point for a separately reviewed process transport.
The emit and wait callbacks must be bounded; the external controller owns the
watchdog because Python cannot interrupt a blocked vendor call safely.
"""

import ctypes
import os
from pathlib import Path

from . import policy as p


class WorkerFailure(Exception):
    pass


class CtypesBackend:
    """Exact dynamic-loading and application call surface, with injectable loader."""

    def __init__(self, paths, *, loader=ctypes.CDLL):
        if set(paths) != set(p.MAPPING_ORDER):
            raise ValueError("exactly three library paths required")
        self.paths = {}
        for name in p.MAPPING_ORDER:
            path = paths[name]
            if not isinstance(path, str) or not Path(path).is_absolute() or ".." in Path(path).parts:
                raise ValueError("absolute normalized library path required")
            self.paths[name] = path
        self.loader = loader
        self.libraries = {}
        self.functions = {}

    def map_library(self, name):
        if name != p.MAPPING_ORDER[len(self.libraries)]:
            raise WorkerFailure("mapping order")
        library = self.loader(self.paths[name], mode=os.RTLD_NOW | os.RTLD_LOCAL)
        self.libraries[name] = library  # Keep alive until process exit; never dlclose.
        names = {"libcudart": ("cudaSetDevice",),
                 "libcublasLt": ("cublasLtCreate", "cublasLtDestroy"),
                 "libcublas": ("cublasCreate_v2", "cublasDestroy_v2")}[name]
        for symbol in names:
            function = getattr(library, symbol)
            function.restype = ctypes.c_int
            function.argtypes = ([ctypes.c_int] if symbol == "cudaSetDevice" else
                                 [ctypes.POINTER(ctypes.c_void_p)] if symbol in p.DESTROY_FOR else
                                 [ctypes.c_void_p])
            self.functions[symbol] = function

    def call(self, name, handle=None):
        if name not in p.CALL_ALLOWLIST or tuple(self.libraries) != p.MAPPING_ORDER:
            raise WorkerFailure("call outside allowlist or before mapping")
        function = self.functions[name]
        if name == "cudaSetDevice":
            return int(function(0)), None
        if name in p.DESTROY_FOR:
            pointer = ctypes.c_void_p()
            status = int(function(ctypes.byref(pointer)))
            return status, pointer.value
        return int(function(ctypes.c_void_p(handle))), None


def run(order, backend, emit, wait_ns, cancelled=lambda: False, clock=p.raw_ns, mapping_gate=None, terminal_gate=None):
    """Execute after RELEASE only. Return raw status records; never translate errors.

    emit receives bounded records, suitable for a preallocated transport. Host
    adapters must not block for observer queries or acknowledgements per call.
    Failed destruction is never retried. Process exit remains the final cleanup.
    """
    if order not in p.CREATE_ORDER:
        raise ValueError("BL or LB required")
    handles, results, errors = [], [], []
    last_ns = -1

    def event(kind, name=None, status=None):
        nonlocal last_ns
        now = clock()
        if type(now) is not int or now < last_ns:
            raise WorkerFailure("clock regression")
        last_ns = now
        emit({"event_type": kind, "call_name": name, "raw_result": status,
              "monotonic_raw_ns": now})

    def invoke(name, handle=None):
        event("CALL_START", name)
        status, created = backend.call(name, handle)
        if type(status) is not int:
            raise WorkerFailure("noninteger vendor status")
        # Register ownership before publishing completion, including sink failure.
        if name in p.DESTROY_FOR and status == 0:
            if not created:
                raise WorkerFailure("successful create returned null handle")
            handles.append((name, created))
        results.append({"call_name": name, "raw_result": status})
        event("CALL_END", name, status)
        if status != 0:
            raise WorkerFailure("vendor status")

    def check_cancelled():
        if cancelled():
            raise WorkerFailure("cancelled")

    try:
        for name in p.MAPPING_ORDER:
            check_cancelled()
            event("CALL_START", name)
            backend.map_library(name)
            event("CALL_END", name, 0)
        if mapping_gate is None or mapping_gate() is not True:
            raise WorkerFailure("post-mapping authorization missing")
        check_cancelled()
        invoke("cudaSetDevice")
        for name in p.CREATE_ORDER[order]:
            check_cancelled()
            invoke(name)
        event("STARTUP_COMPLETE")
        wait_ns(p.DWELL_NS)
        check_cancelled()
        event("DWELL_COMPLETE")
    except Exception as exc:
        # Exception messages may contain vendor text/paths; record only class.
        errors.append(type(exc).__name__)
    finally:
        try:
            event("CLEANUP_RELEASE")
        except Exception as exc:
            errors.append(type(exc).__name__)
        while handles:
            name, handle = handles.pop()
            try:
                # Cleanup must still run if publishing CALL_START fails.
                try:
                    event("CALL_START", p.DESTROY_FOR[name])
                except Exception as exc:
                    errors.append(type(exc).__name__)
                status, _ = backend.call(p.DESTROY_FOR[name], handle)
                if type(status) is not int:
                    raise WorkerFailure("noninteger vendor status")
                results.append({"call_name": p.DESTROY_FOR[name], "raw_result": status})
                event("CALL_END", p.DESTROY_FOR[name], status)
                if status != 0:
                    errors.append("WorkerFailure")
            except Exception as exc:
                errors.append(type(exc).__name__)
        try:
            if terminal_gate is None or terminal_gate() is not True:
                raise WorkerFailure("terminal mapping continuity missing")
        except Exception as exc:
            errors.append(type(exc).__name__)
        try:
            event("CLEANUP_COMPLETE")
        except Exception as exc:
            errors.append(type(exc).__name__)
    return {"call_results": results, "errors": errors,
            "exit_code": 1 if errors else 0}
