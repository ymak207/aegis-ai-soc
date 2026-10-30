#!/usr/bin/env python3
"""Resolve deployed OpenAPI request schemas without mutating AEGIS."""
import json
import os
from pathlib import Path
from urllib.request import urlopen

BASE = os.getenv("AEGIS_BASE_URL", "http://127.0.0.1:8000").rstrip("/")
OUT = Path("test-artifacts/phase-01/results")
OUT.mkdir(parents=True, exist_ok=True)

with urlopen(BASE + "/openapi.json", timeout=20) as response:
    spec = json.load(response)

(OUT / "openapi.json").write_text(json.dumps(spec, indent=2), encoding="utf-8")

def resolve(ref):
    if not ref.startswith("#/"):
        return {"$unresolved_ref": ref}
    node = spec
    for part in ref[2:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        node = node[part]
    return node

targets = [
    ("/api/v1/events", "post"),
    ("/api/v1/events/batch", "post"),
    ("/api/v1/lab/run", "post"),
    ("/api/v1/sources", "post"),
    ("/api/v1/sources/import", "post"),
    ("/api/v1/investigations", "post"),
    ("/api/v1/cases", "post"),
    ("/api/v1/intel/indicators", "post"),
    ("/api/v1/knowledge/documents", "post"),
]
result = {"api": spec.get("info", {}), "operations": []}
for path, method in targets:
    operation = spec.get("paths", {}).get(path, {}).get(method)
    if not operation:
        result["operations"].append({"path": path, "method": method.upper(), "found": False})
        continue
    for content_type, body in operation.get("requestBody", {}).get("content", {}).items():
        schema = body.get("schema", {})
        resolved = resolve(schema["$ref"]) if "$ref" in schema else schema
        result["operations"].append({
            "path": path, "method": method.upper(),
            "content_type": content_type, "schema": resolved
        })

(OUT / "request_schemas.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
print("API:", result["api"].get("title"), result["api"].get("version"))
print("Saved:", OUT / "openapi.json")
print("Saved:", OUT / "request_schemas.json")
for op in result["operations"]:
    print("\\n", op["method"], op["path"])
    print(json.dumps(op.get("schema", {"found": False}), indent=2))
