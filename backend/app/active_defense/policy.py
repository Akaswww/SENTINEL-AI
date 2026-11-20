import hashlib
import ipaddress
import os
import stat
from pathlib import Path
import psutil

# Deliberately restricted to the current user's dedicated lab directory.
LAB_ROOT = (Path.home() / 'sentinel-defense-lab').resolve()
PROTECTED_NAMES = {'launchd', 'kernel_task', 'WindowServer', 'loginwindow', 'securityd', 'sshd'}

class PolicyError(ValueError):
    pass

def validate_ip(value: str) -> str:
    try:
        addr = ipaddress.ip_address(value.strip())
    except ValueError as exc:
        raise PolicyError('Invalid IP address') from exc
    if not addr.is_global:
        raise PolicyError('Only global unicast IPs are eligible')
    return str(addr)

def validate_file(value: str) -> tuple[str, str]:
    candidate = Path(value).expanduser()
    if candidate.is_symlink():
        raise PolicyError('Symlinks are not eligible')
    path = candidate.resolve(strict=True)
    if not path.is_relative_to(LAB_ROOT) or path == LAB_ROOT:
        raise PolicyError(f'File must be inside {LAB_ROOT}')
    st = path.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or st.st_nlink != 1:
        raise PolicyError('Only single-link, user-owned regular files are eligible')
    if st.st_size > 50 * 1024 * 1024:
        raise PolicyError('File exceeds 50 MiB lab limit')
    with path.open('rb') as f:
        digest = hashlib.file_digest(f, 'sha256').hexdigest()
    return str(path), f'{st.st_dev}:{st.st_ino}:{st.st_size}:{st.st_mtime_ns}:{digest}'

def validate_process(value: str) -> tuple[str, str]:
    try:
        pid = int(value)
        p = psutil.Process(pid)
        if pid <= 1 or p.uids().real != os.getuid() or p.name() in PROTECTED_NAMES:
            raise PolicyError('Protected or non-owned process')
        exe = p.exe()
        # Require lab executable; never stop normal user applications.
        if not Path(exe).resolve().is_relative_to(LAB_ROOT):
            raise PolicyError('Process executable is outside lab directory')
        fingerprint = f'{pid}:{p.create_time()}:{exe}'
        return str(pid), fingerprint
    except (ValueError, psutil.Error, OSError) as exc:
        if isinstance(exc, PolicyError):
            raise
        raise PolicyError('Process not available or inaccessible') from exc

def validate(action: str, target: str) -> tuple[str, str | None]:
    if action == 'block_ip':
        return validate_ip(target), None
    if action == 'quarantine_file':
        return validate_file(target)
    if action == 'terminate_process':
        return validate_process(target)
    raise PolicyError('Unsupported action')
