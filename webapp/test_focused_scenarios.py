"""Exercise focused scenarios through the dashboard, including model calls."""
import asyncio
import httpx


async def main():
    async with httpx.AsyncClient(base_url="http://127.0.0.1:8765", timeout=30) as client:
        failed = []
        for scenario in ("triage", "report", "rules"):
            response = await client.post("/api/runs", json={"pipeline": scenario})
            response.raise_for_status()
            run_id = response.json()["id"]
            for _ in range(480):
                response = await client.get(f"/api/runs/{run_id}")
                response.raise_for_status()
                run = response.json()
                if run["status"] not in ("running", "queued"):
                    print(scenario, run["status"], run.get("results"), run.get("error"), flush=True)
                    if run["status"] != "completed":
                        failed.append(scenario)
                    break
                await asyncio.sleep(5)
            else:
                raise TimeoutError(scenario)
        if failed:
            raise RuntimeError(f"Scenarios failed: {failed}")


if __name__ == "__main__":
    asyncio.run(main())
