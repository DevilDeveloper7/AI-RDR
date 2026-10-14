"""
AI-RDR  |  M3 Honey-File / Deception path
m3_checkpoint1.py  --  Checkpoint 1 (setup only, NO event-trigger logic)

What this script does, in order:
  1. Creates an isolated TEST directory with simple placeholder decoys,
     plus one NON-decoy control file.
  2. Builds the Decoy_Registry (exact paths) and saves it to registry.json.
  3. Establishes inotify watches on the parent directory of the decoys.
  4. Prints exactly what is registered and what is being watched.
  5. Closes the watches and exits. It does NOT read or handle any events yet.

Nothing here is a production decision:
  - the test folder is NOT the final decoy-placement location
  - the WATCH_MASK is prepared for checkpoint 2 but no events are consumed now
"""

import os
from inotify_simple import INotify, flags
from decoy_registry import DecoyRegistry

# ---- isolated test area (implementation-local / test-only) ---------------
BASE = os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_lab")
DECOY_DIR = os.path.join(BASE, "documents")
REGISTRY_FILE = os.path.join(BASE, "registry.json")

# placeholder decoys (plain text; no realism logic in this card)
PLACEHOLDER_DECOYS = ["report.txt", "budget.txt", "notes.txt"]
CONTROL_FILE = "real_user_file.txt"   # NOT a decoy -- used later as negative test

# event mask prepared for checkpoint 2; watches are established with it now
# but no events are read in this checkpoint.
WATCH_MASK = (
    flags.ACCESS | flags.OPEN | flags.MODIFY | flags.CLOSE_WRITE
    | flags.MOVED_FROM | flags.MOVED_TO | flags.CREATE
    | flags.DELETE | flags.DELETE_SELF | flags.ATTRIB
)


def build_test_files():
    os.makedirs(DECOY_DIR, exist_ok=True)
    for name in PLACEHOLDER_DECOYS:
        p = os.path.join(DECOY_DIR, name)
        if not os.path.exists(p):
            with open(p, "w", encoding="utf-8") as f:
                f.write("placeholder decoy content\n")
    ctrl = os.path.join(DECOY_DIR, CONTROL_FILE)
    if not os.path.exists(ctrl):
        with open(ctrl, "w", encoding="utf-8") as f:
            f.write("ordinary non-decoy file\n")


def build_registry():
    reg = DecoyRegistry()
    for name in PLACEHOLDER_DECOYS:
        reg.add(os.path.join(DECOY_DIR, name))
    reg.save(REGISTRY_FILE)
    return reg


def establish_watches(reg):
    inotify = INotify()
    wd_map = {}
    for d in reg.watch_dirs():
        wd = inotify.add_watch(d, WATCH_MASK)
        wd_map[wd] = d
    return inotify, wd_map


def main():
    build_test_files()
    reg = build_registry()

    print("=" * 60)
    print("AI-RDR  M3  |  Checkpoint 1  (setup only, no triggers)")
    print("=" * 60)

    print(f"\nRegistry file : {REGISTRY_FILE}")
    print(f"Registered decoys ({len(reg.active_decoys())}):")
    for d in reg.active_decoys():
        print(f"  [{d['decoy_id']}] {d['path']}")

    ctrl = os.path.realpath(os.path.join(DECOY_DIR, CONTROL_FILE))
    print(f"\nControl file (NOT registered): {ctrl}")
    print(f"  is_registered_decoy() -> {reg.is_registered_decoy(ctrl)}   (expected: False)")

    inotify, wd_map = establish_watches(reg)
    print(f"\nWatched directories ({len(wd_map)}):")
    for wd, d in wd_map.items():
        names = [x["path"].split(os.sep)[-1] for x in reg.decoys_in(d)]
        print(f"  wd={wd}  dir={d}")
        print(f"          decoys here: {', '.join(names)}")

    inotify.close()
    print("\nWatches established and then closed cleanly. No events were read.")
    print("Checkpoint 1 complete.")


if __name__ == "__main__":
    main()
