"""Exercise every dashboard scenario against the running local server (real model spend).

    uv run python -m webapp.test_scenarios
"""
import asyncio
import time

import httpx


async def main():
    async with httpx.AsyncClient(base_url="http://127.0.0.1:8765", timeout=30) as client:
        async def wait(run_id):
            deadline = time.monotonic() + 7200
            last = None
            while time.monotonic() < deadline:
                response = await client.get(f"/api/runs/{run_id}")
                response.raise_for_status()
                run = response.json()
                message = (run["status"], run.get("message"))
                if message != last:
                    print(run_id[:8], *message, flush=True)
                    last = message
                if run["status"] not in ("queued", "running"):
                    print("RESULT", run["pipeline"], run["status"], run.get("results"), run.get("error"), run.get("export_error"), flush=True)
                    return run["status"] == "completed" and not run.get("export_error")
                await asyncio.sleep(5)
            raise TimeoutError(f"Run {run_id} did not finish within two hours")

        response = await client.get("/api/runs")
        response.raise_for_status()
        active = [r for r in response.json() if r["status"] in ("queued", "running")]
        passed = []
        for run in active:
            passed.append(await wait(run["id"]))
        for pipeline in ("smoke", "triage", "report", "rules", "v2", "v3"):
            response = await client.post("/api/runs", json={"pipeline": pipeline})
            response.raise_for_status()
            passed.append(await wait(response.json()["id"]))
        print("SUITE", "PASS" if all(passed) else "FAIL", flush=True)
        if not all(passed):
            raise SystemExit(1)


if __name__ == "__main__":
    asyncio.run(main())
