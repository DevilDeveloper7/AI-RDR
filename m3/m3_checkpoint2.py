
"""
AI-RDR | M3 Honey-File Deception
Checkpoint 2 - Steps A and B

Step A: Keep the file watcher running.
Step B: Read and display file activity detected by Linux.

This is a test environment. Alerts will be added in later steps.
"""

import os
import time
from inotify_simple import INotify, flags
from decoy_registry import DecoyRegistry
from datetime import datetime

# Test folder and registry locations
BASE = os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_lab")
DECOY_DIR = os.path.join(BASE, "documents")
REGISTRY_FILE = os.path.join(BASE, "registry.json")

PLACEHOLDER_DECOYS = ["report.txt", "budget.txt", "notes.txt"]
CONTROL_FILE = "real_user_file.txt"

# File activities that Linux should monitor
WATCH_MASK = (
    flags.ACCESS
    | flags.OPEN
    | flags.MODIFY
    | flags.CLOSE_WRITE
    | flags.MOVED_FROM
    | flags.MOVED_TO
    | flags.CREATE
    | flags.DELETE
    | flags.DELETE_SELF
    | flags.ATTRIB
)


def build_test_files():
    """Create three honeyfiles and one normal file."""

    os.makedirs(DECOY_DIR, exist_ok=True)

    for name in PLACEHOLDER_DECOYS:
        path = os.path.join(DECOY_DIR, name)

        if not os.path.exists(path):
            with open(path, "w", encoding="utf-8") as f:
                f.write("placeholder decoy content\n")

    control_path = os.path.join(DECOY_DIR, CONTROL_FILE)

    if not os.path.exists(control_path):
        with open(control_path, "w", encoding="utf-8") as f:
            f.write("ordinary non-decoy file\n")


def build_registry():
    """Register the honeyfiles."""

    reg = DecoyRegistry()

    for name in PLACEHOLDER_DECOYS:
        reg.add(os.path.join(DECOY_DIR, name))

    reg.save(REGISTRY_FILE)

    return reg


def establish_watches(reg):
    """Start monitoring the folders containing honeyfiles."""

    inotify = INotify()
    wd_map = {}

    for directory in reg.watch_dirs():
        wd = inotify.add_watch(directory, WATCH_MASK)
        wd_map[wd] = directory

    return inotify, wd_map


def main():

    build_test_files()
    reg = build_registry()

    print("=" * 60)
    print("AI-RDR M3 | Checkpoint 2 - Steps A and B")
    print("=" * 60)
    last_alert_time = {}
    COOLDOWN_SECONDS = 5

    print(f"\nRegistry file: {REGISTRY_FILE}")

    print(f"\nRegistered decoys ({len(reg.active_decoys())}):")

    for decoy in reg.active_decoys():
        print(f"  [{decoy['decoy_id']}] {decoy['path']}")

    # Step A: Establish persistent watches
    inotify, wd_map = establish_watches(reg)

    print(f"\nWatched directories ({len(wd_map)}):")

    for wd, directory in wd_map.items():
        names = [
            decoy["path"].split(os.sep)[-1]
            for decoy in reg.decoys_in(directory)
        ]

        print(f"  wd={wd}  dir={directory}")
        print(f"  Decoys here: {', '.join(names)}")

    print("\nWatcher is running. Press Ctrl+C to stop.")

    try:
        while True:

            # Step B: Read and display file events
            for event in inotify.read():

                # Identify the type of activity
                event_types = flags.from_mask(event.mask)

                # Find the folder where the event happened
                folder = wd_map.get(event.wd, "")

                # Reconstruct the file path
                file_path = os.path.join(folder, event.name)

                # Display the detected event
                print(f"Event: {event_types} | File: {file_path}")
                is_honeyfile = reg.is_registered_decoy(file_path)
                print(f"File type : {'HONEYFILE' if is_honeyfile else 'NORMAL FILE'}")
                if is_honeyfile and (flags.CLOSE_WRITE in event_types or flags.ACCESS in event_types):
                    now = time.monotonic()
                    if now - last_alert_time.get(file_path, 0) < COOLDOWN_SECONDS:
                        continue
                    decoy = next(
                        d for d in reg.active_decoys() if d["path"] == os.path.realpath(file_path)
                    )
                    alert_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    print(f"!!! HONEYFILE ALERT !!! Time: {alert_time}")
                    print(f"File: {file_path}")
                    print(f"Decoy ID: {decoy['decoy_id']}")
                    print(f"Event: {event_types}")
                    last_alert_time[file_path] = now
    except KeyboardInterrupt:
        print("\nCtrl+C received -- shutting down.")

    finally:
        inotify.close()
        print("Watches closed cleanly. Checkpoint 2 Steps A and B complete.")


if __name__ == "__main__":
    main()
