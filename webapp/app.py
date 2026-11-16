"""Run with: uv run python -m webapp.app. Intended for this laptop only."""
import json
import os
import re
import subprocess
import sys
import uuid
import fcntl
from contextlib import contextmanager
from threading import Lock
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from markdown_it import MarkdownIt

from webapp.store import PIPELINES, ROOT, STATE, read, save
from webapp.workflow import workflow
from grading import assess
from webapp.models import verified_models

app = FastAPI(title="Cyber Eval Console")
markdown = MarkdownIt("commonmark", {"html": False}).enable("table")
launch_lock = Lock()
app.mount("/static", StaticFiles(directory=Path(__file__).parent / "static"), name="static")


@contextmanager
def launch_guard():
    with launch_lock:
        STATE.mkdir(parents=True, exist_ok=True)
        with (STATE / "launch.lock").open("w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            yield


@app.middleware("http")
async def local_only(request: Request, call_next):
    host = request.url.hostname
    if host not in ("127.0.0.1", "localhost", "::1", "testserver"):
        return PlainTextResponse("Local access only", status_code=403)
    if request.method == "POST":
        origin = request.headers.get("origin")
        if origin and urlsplit(origin).netloc != request.headers.get("host"):
            return PlainTextResponse("Cross-origin launch refused", status_code=403)
    response = await call_next(request)
    if request.url.path == "/" or request.url.path.startswith(("/static/", "/api/")):
        response.headers["Cache-Control"] = "no-store"
    return response


class Launch(BaseModel):
    pipeline: str = "smoke"
    model: str = ""
    judge_model: str = ""


class BatchLaunch(BaseModel):
    pipelines: list[str] = Field(min_length=1, max_length=7)
    k: int = Field(default=1, ge=1, le=20, strict=True)
    model: str = ""
    judge_model: str = ""
    success_threshold: float = Field(default=.8, ge=0, le=1)


def validate_models(model, judge):
    for value in (model, judge):
        if value and (len(value) > 160 or not re.fullmatch(r"[a-zA-Z0-9_./:-]+", value)):
            raise HTTPException(422, "Invalid model identifier")
    defaults = model_config()
    model, judge = model or defaults["analyst_model"], judge or defaults["judge_model"]
    models = {m["id"] for m in available_models()}
    if model not in models or judge not in models:
        raise HTTPException(422, "Model is not in the saved available-model list. Refresh models and select an available option.")
    return model, judge


@app.get("/api/batches")
def batches():
    from webapp.batches import batch_detail
    return sorted([batch_detail(path.parent, state=STATE) for path in (STATE / "batches").glob("*/batch.json")],
                  key=lambda b: b["created_at"], reverse=True)


@app.post("/api/batches", status_code=201)
def launch_batch(body: BatchLaunch):
    from webapp.batches import create_batch
    with launch_guard():
        if len(set(body.pipelines)) != len(body.pipelines) or any(p not in PIPELINES for p in body.pipelines):
            raise HTTPException(422, "Select distinct known scenarios")
        if len(body.pipelines) * body.k > 40:
            raise HTTPException(422, "A batch may contain at most 40 trials")
        if any(b["status"] in ("queued", "running") for b in batches()) or any(r["status"] in ("queued", "running") for r in runs()):
            raise HTTPException(409, "A dashboard run or batch is already active")
        model, judge = body.model, body.judge_model
        if any(PIPELINES[p]["model"] for p in body.pipelines):
            model, judge = validate_models(model, judge)
        else:
            defaults = model_config()
            model, judge = defaults["analyst_model"], defaults["judge_model"]
        # Scheduling is internal; users choose what to evaluate, not worker counts.
        return create_batch(body.pipelines, body.k, 2, model, judge, body.success_threshold,
                            state=STATE, root=ROOT)


def folder_for(run_id):
    if not re.fullmatch(r"[a-f0-9]{32}", run_id):
        raise HTTPException(404, "Run not found")
    folder = STATE / run_id
    if not (folder / "run.json").is_file():
        raise HTTPException(404, "Run not found")
    return folder


def detail(folder):
    record = read(folder)
    heartbeat = folder / "heartbeat"
    record["heartbeat_at"] = heartbeat.read_text() if heartbeat.exists() else None
    if (folder / "pid").exists():
        record["pid"] = int((folder / "pid").read_text())
    if record["status"] in ("queued", "running") and record.get("pid"):
        try:
            os.kill(record["pid"], 0)
        except ProcessLookupError:
            record.update(status="interrupted", error="Worker exited before recording completion; inspect its log.")
    elif record["status"] == "queued" and record.get("batch_id"):
        from webapp.batches import batch_detail
        folder = STATE / "batches" / record["batch_id"]
        if (folder / "batch.json").exists():
            batch_detail(folder, state=STATE)
            record = read(STATE / record["id"])
    return record


@app.get("/")
def index():
    return FileResponse(Path(__file__).parent / "static/index.html", headers={"Cache-Control": "no-store"})


@app.get("/api/pipelines")
def pipelines():
    return [{"id": k, "steps": workflow(k), **{f: v[f] for f in ("name", "description", "model")}} for k, v in PIPELINES.items()]


@app.get("/api/pipelines/{pipeline}/workflow")
def pipeline_workflow(pipeline: str):
    if pipeline not in PIPELINES:
        raise HTTPException(404, "Unknown workflow")
    return {"name": PIPELINES[pipeline]["name"], "steps": workflow(pipeline)}


@app.get("/api/pipelines/{pipeline}/rubric")
def scenario_rubric(pipeline: str):
    if pipeline not in PIPELINES:
        raise HTTPException(404, "Unknown scenario")
    from webapp.reporting import rubric
    bundle = ROOT / PIPELINES[pipeline]["bundle"]
    steps = [s for path in sorted((bundle / "tasks").glob("*.json")) for s in json.loads(path.read_text())]
    return PlainTextResponse(rubric(steps, bundle), headers={"Content-Disposition": 'inline; filename="rubric.md"'})


@app.get("/api/models/config")
def model_config():
    endpoint = os.getenv("LITELLM_BASE_URL", "")
    return {"ready": bool(endpoint and os.getenv("LITELLM_API_KEY")),
            "endpoint": urlsplit(endpoint).netloc.rsplit("@", 1)[-1],
            "analyst_model": os.getenv("CYBER_ANALYST_MODEL", "openai/openai/gpt-5"),
            "judge_model": os.getenv("CYBER_JUDGE_MODEL", "openai/openai/gpt-6-sol")}


@app.get("/api/models")
def available_models():
    try:
        return verified_models()
    except ValueError as exc:
        raise HTTPException(503, str(exc)) from None


@app.get("/api/runs")
def runs():
    records = [detail(p.parent) for p in STATE.glob("*/run.json")]
    return sorted(records, key=lambda r: r["created_at"], reverse=True)


@app.post("/api/runs", status_code=201)
def launch(body: Launch):
    with launch_guard():
        return launch_run(body)


def launch_run(body):
    if body.pipeline not in PIPELINES:
        raise HTTPException(422, "Unknown pipeline")
    for model in (body.model, body.judge_model):
        if model and (len(model) > 160 or not re.fullmatch(r"[a-zA-Z0-9_./:-]+", model)):
            raise HTTPException(422, "Invalid model identifier")
    if any(r["status"] in ("queued", "running") for r in runs()):
        raise HTTPException(409, "A dashboard run is already active")
    if any(b["status"] in ("queued", "running") for b in batches()):
        raise HTTPException(409, "A dashboard batch is already active")
    if PIPELINES[body.pipeline]["model"]:
        models = {m["id"] for m in available_models()}
        defaults = model_config()
        for model, role in ((body.model or defaults["analyst_model"], "analyst"),
                            (body.judge_model or defaults["judge_model"], "judge")):
            if model not in models:
                raise HTTPException(422, "Model is not in the saved available-model list. Refresh models and select an available option.")
    run_id = uuid.uuid4().hex
    folder = STATE / run_id
    record = {"id": run_id, "pipeline": body.pipeline, "name": PIPELINES[body.pipeline]["name"],
              "model": body.model if PIPELINES[body.pipeline]["model"] else "", "status": "queued",
              "judge_model": body.judge_model if PIPELINES[body.pipeline]["model"] else "",
              "created_at": datetime.now(timezone.utc).isoformat(), "steps": {}, "message": "Starting AEF worker"}
    save(folder, record)
    with (folder / "output.log").open("w") as log:
        process = subprocess.Popen([sys.executable, "-u", "-m", "webapp.worker", run_id], cwd=ROOT,
                                   stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
    # The worker can update immediately: don't overwrite its progress with our queued record.
    (folder / "pid").write_text(str(process.pid))
    return record


@app.get("/api/runs/{run_id}")
def run_detail(run_id: str):
    folder = folder_for(run_id)
    record = detail(folder)
    record["workflow"] = record.get("workflow") or (workflow(record["pipeline"]) if record.get("pipeline") in PIPELINES else [])
    log = folder / "output.log"
    if log.exists():
        with log.open("rb") as stream:
            stream.seek(max(0, log.stat().st_size - 32000))
            record["log"] = stream.read().decode(errors="replace")
    result = folder / "results.json"
    record["verifications"] = []
    if result.exists():
        for r in json.loads(result.read_text()):
            verifications = r["context"].get("metadata", {}).get("verifications", {})
            rows = verifications.get("facts", {}).get("results", [])
            for score_id in ("soc-v1", "soc-v2", "soc-v3"):
                if score_id in r.get("scores", {}):
                    grade = assess(r["scores"][score_id], rows)
                    for summary in record.get("results", []):
                        if summary["instance_id"] == r["instance_id"]:
                            summary.setdefault("grading", {})[score_id] = grade
                            summary["scores"][score_id] = grade["score"]
            record["verifications"].append({"instance_id": r["instance_id"],
                "checks": r["context"].get("metadata", {}).get("verifications", {})})
    record["files"] = []
    if record.get("export_path"):
        root = (ROOT / record["export_path"]).resolve()
        if root.is_relative_to((ROOT / "runs").resolve()) and root.exists():
            record["files"] = sorted(str(p.relative_to(root)) for p in root.rglob("*") if p.is_file())
    return record


@app.get("/api/runs/{run_id}/files/{filename:path}")
def result_file(run_id: str, filename: str):
    record = read(folder_for(run_id))
    if not record.get("export_path"):
        raise HTTPException(404, "No exported results")
    root = (ROOT / record["export_path"]).resolve()
    path = (root / filename).resolve()
    if not root.is_relative_to((ROOT / "runs").resolve()) or not path.is_relative_to(root) or not path.is_file():
        raise HTTPException(404, "File not found")
    # Never execute or render agent-produced HTML/JavaScript.
    return PlainTextResponse(path.read_text(errors="replace"))


@app.get("/api/runs/{run_id}/inputs")
def agent_inputs(run_id: str):
    from webapp.inputs import run_inputs
    folder = folder_for(run_id)
    return run_inputs(folder, read(folder), ROOT)


@app.get("/api/runs/{run_id}/render/{filename:path}")
def rendered_file(run_id: str, filename: str):
    if not filename.lower().endswith(".md"):
        raise HTTPException(422, "Only Markdown reports can be rendered")
    response = result_file(run_id, filename)
    # Raw HTML is disabled and markdown-it rejects unsafe link schemes. Return JSON,
    # never a standalone executable document. The viewer only inserts this parsed markup.
    return {"html": markdown.render(response.body.decode())}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8765)
