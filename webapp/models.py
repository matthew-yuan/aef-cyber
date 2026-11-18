"""Persistent list of working chat model aliases, shared by both model selectors."""
import hashlib
import json
import os
from datetime import datetime, timezone
from threading import Lock

import httpx
from webapp.store import STATE

_lock = Lock()


def coordinates():
    from agent_env.config import ConfigError, get_config

    config = get_config()
    try:
        endpoint = config.get_litellm_base_url().rstrip("/")
        key = config.get_litellm_api_key()
    except ConfigError:
        endpoint, key = "", ""
    if not endpoint or not key:
        raise ValueError("Configure the model endpoint and API key in .agentenv/config.toml or LITELLM_* variables")
    # Scope by credentials without persisting the key or its unsalted hash.
    scope = hashlib.sha256((endpoint + "\0" + key).encode()).hexdigest()
    return endpoint, key, STATE / "models" / f"{scope}.json"


def save_catalog(path, catalog):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(catalog, indent=2))
    temporary.replace(path)


def working_model(endpoint, key, alias):
    try:
        response = httpx.post(f"{endpoint}/chat/completions", timeout=25,
                             headers={"Authorization": f"Bearer {key}"}, json={
                                 "model": alias, "messages": [{"role": "user", "content": "Reply OK."}],
                                 "max_completion_tokens": 256})
        response.raise_for_status()
        return bool(response.json().get("choices"))
    except (httpx.HTTPError, ValueError, TypeError):
        return False


def verified_models():
    _, _, path = coordinates()
    with _lock:
        if not path.exists():
            raise ValueError("Model list is being prepared. Run `uv run python -m webapp.scan_models` once, then refresh models.")
        catalog = json.loads(path.read_text())
        return [{"id": "openai/" + alias, "name": alias} for alias, ok in sorted(catalog["checks"].items()) if ok]


def scan_models():
    """Resume a one-time scan; never recheck an alias already saved in this catalog."""
    from concurrent.futures import ThreadPoolExecutor, as_completed
    endpoint, key, path = coordinates()
    catalog = json.loads(path.read_text()) if path.exists() else {"checks": {}, "checked_at": None}
    response = httpx.get(endpoint.removesuffix("/v1") + "/model/info", timeout=180,
                         headers={"Authorization": f"Bearer {key}"})
    response.raise_for_status()
    aliases = sorted({row["model_name"] for row in response.json()["data"]
                      if row.get("model_info", {}).get("mode") == "chat"})
    pending = [a for a in aliases if a not in catalog["checks"]]
    print(f"Chat aliases: {len(aliases)}; already checked: {len(catalog['checks'])}; pending: {len(pending)}", flush=True)
    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = {pool.submit(working_model, endpoint, key, alias): alias for alias in pending}
        for i, future in enumerate(as_completed(futures), 1):
            catalog["checks"][futures[future]] = future.result()
            catalog["checked_at"] = datetime.now(timezone.utc).isoformat()
            save_catalog(path, catalog)
            if i % 25 == 0:
                print(f"Checked {i}/{len(pending)}; available: {sum(catalog['checks'].values())}", flush=True)
    print(f"Saved {sum(catalog['checks'].values())} available models in {path}", flush=True)
