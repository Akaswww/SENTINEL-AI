
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from network_monitor import get_network_connections

OUTPUT = Path(__file__).resolve().parent / "network_snapshot.json"

def main():
    snapshot = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "connections": get_network_connections(),
    }

    # Atomic replacement prevents partially written JSON.
    fd, temporary = tempfile.mkstemp(
        prefix=".network-",
        dir=OUTPUT.parent,
    )

    try:
        with os.fdopen(fd, "w") as file:
            json.dump(snapshot, file)
        os.chmod(temporary, 0o600)
        os.replace(temporary, OUTPUT)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)

    print(
        f"Collected {len(snapshot['connections'])} connections"
    )


if __name__ == "__main__":
    main()
