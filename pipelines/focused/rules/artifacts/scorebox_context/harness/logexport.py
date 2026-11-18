"""logexport: the one definition of the data object analyst code receives.

`build_export(incident)` turns an incident.json into `{"incident_id", "sources": [...], "auth": [...], "dns": [...],
"proxy": [...], "endpoint": [...]}` with every record carrying its `id` and a `source` field. The data builder writes
it to soc-env/data/log_export.json, the lab builds it in memory from the incident it is seeded with, and the scoring
image ships the written file, so all three see the same object.
"""
SOURCES = ("auth", "dns", "proxy", "endpoint")


def build_export(incident: dict) -> dict:
    export = {"incident_id": incident.get("metadata", {}).get("incident_id"), "sources": list(SOURCES)}
    for source in SOURCES:
        export[source] = [
            {"id": r.get("id"), "source": source, **{k: v for k, v in r.items() if k not in ("id", "source")}}
            for r in incident.get("logs", {}).get(source, [])
        ]
    return export
