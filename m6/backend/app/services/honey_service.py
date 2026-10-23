from ..integrations import contracts as C


def honey_files(m3):
    """Honey-file status from M3, plus the summary numbers the UI shows."""
    data = m3.list_honey_files()
    items = [C.validate_honey_item(i) for i in data["items"]]
    triggered = [i for i in items if i["status"] == "Triggered"]
    last = max(triggered, key=lambda i: i["last_event"], default=None)
    hosts = {i["host"] for i in items}
    return {
        "summary": {
            "watcher_status": data["watcher_status"],
            "total_files": len(items),
            "monitored_hosts": len(hosts), "total_hosts": len(hosts),
            "healthy": len(items) - len(triggered),
            "triggered": len(triggered),
            "triggered_hosts": [i["host"] for i in triggered],
            "last_interaction": {"time": last["last_event"], "host": last["host"]} if last else None,
        },
        "items": items,
        "activity": data["activity"],
        "meta": {"is_mock": True},
    }
