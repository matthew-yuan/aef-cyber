"""List proxy models, or test the same AEF inference path the rubric judges use.

    uv run python model_smoke_test.py --list
    uv run python model_smoke_test.py openai/<proxy-model-id>
"""
import argparse
import os

import httpx
import litellm
from agent_env.config import get_config


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("model", nargs="?", default="openai/openai/gpt-5")
    parser.add_argument("--list", action="store_true")
    args = parser.parse_args()
    if not os.getenv("LITELLM_BASE_URL") or not os.getenv("LITELLM_API_KEY"):
        parser.error("Export LITELLM_BASE_URL and LITELLM_API_KEY first")
    call = get_config().resolve_model_call(args.model)
    if args.list:
        response = httpx.get(f"{call.api_base.rstrip('/')}/models", timeout=30,
                             headers={"Authorization": "Bearer " + os.environ["LITELLM_API_KEY"]})
        response.raise_for_status()
        for model in response.json().get("data", []):
            print(model["id"])
    else:
        result = litellm.completion(model=args.model, timeout=60, max_tokens=200,
                                    messages=[{"role": "user", "content": "Reply with exactly: LITELLM OK"}],
                                    **call.client_kwargs())
        print(result.choices[0].message.content)


if __name__ == "__main__":
    main()
