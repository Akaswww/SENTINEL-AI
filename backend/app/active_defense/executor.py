"""Restricted lab executor. No shell, sudo, or arbitrary command execution."""
import os
import shutil
import signal
from pathlib import Path
import psutil
from .policy import LAB_ROOT, PolicyError, validate

QUARANTINE = LAB_ROOT / '.quarantine'

def execute(action_id: int, action: str, target: str, fingerprint: str | None) -> tuple[str, bool]:
    # Revalidate immediately before changing anything.
    validated, current = validate(action, target)
    if validated != target or current != fingerprint:
        raise PolicyError('Target changed since approval request')
    if action == 'block_ip':
        # Real pf modification must use a separately reviewed privileged helper.
        return 'NOT_EXECUTED: macOS pf helper is not installed; firewall unchanged', False
    if action == 'quarantine_file':
        QUARANTINE.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(QUARANTINE, 0o700)
        source = Path(target)
        dest = QUARANTINE / f'{action_id}-{source.name}'
        if dest.exists():
            raise PolicyError('Quarantine destination already exists')
        # Same-filesystem atomic rename; fail rather than copying across devices.
        if source.stat().st_dev != QUARANTINE.stat().st_dev:
            raise PolicyError('Cross-device quarantine is disabled')
        source.rename(dest)
        os.chmod(dest, 0o600)
        return f'Quarantined to {dest}', True
    if action == 'terminate_process':
        p = psutil.Process(int(target))
        # Prevent PID reuse between validation and termination.
        if f'{p.pid}:{p.create_time()}:{p.exe()}' != fingerprint:
            raise PolicyError('Process identity changed')
        p.terminate()  # SIGTERM, not SIGKILL
        try:
            p.wait(timeout=3)
            return f'SIGTERM sent and PID {target} exited', False
        except psutil.TimeoutExpired:
            return f'SIGTERM sent to PID {target}; exit not confirmed', False
    raise PolicyError('Unsupported action')
