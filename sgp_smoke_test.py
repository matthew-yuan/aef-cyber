"""Smoke-test SGP through agent-env's own model-call path.

Resolves the call the same way agent-env's verifiers do (base_url, api_key and
[model.headers] from .agentenv/config.toml), then sends one LiteLLM completion.

    uv run python sgp_smoke_test.py --list                         # list models on the account
    uv run python sgp_smoke_test.py openai/anthropic/<model-name>  # one chat completion

Needs SGP_API_KEY and SGP_ACCOUNT_ID exported in the shell.
"""

from __future__ import annotations

import argparse
import os
import sys

import httpx
import litellm

from agent_env.config.runtime import get_config


def list_models(base_url: str, headers: dict[str, str]) -> None:
    resp = httpx.get(f"{base_url.rstrip('/')}/models", headers=headers, timeout=30)
    resp.raise_for_status()
    body = resp.json()
    items = body.get("items") or body.get("data") or body
    for item in items:
        print(f"{item.get('name')}  (vendor={item.get('model_vendor')}, status={item.get('status')})")


def complete(model: str, max_tokens: int) -> None:
    call = get_config().resolve_model_call(model)
    print(f"api_base={call.api_base}  headers={sorted(call.params.get('extra_headers', {}))}")
    response = litellm.completion(
        model=model,
        messages=[{"role": "user", "content": "Reply with exactly: SGP OK"}],
        max_tokens=max_tokens,
        timeout=60,
        **call.client_kwargs(),
    )
    print(f"model={response.model}")
    print(f"reply={response.choices[0].message.content!r}  finish_reason={response.choices[0].finish_reason}")
    print(f"usage={response.usage}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("model", nargs="?", help="LiteLLM model name, e.g. openai/anthropic/<model>")
    parser.add_argument("--list", action="store_true", help="list models the SGP account can see")
    parser.add_argument("--max-tokens", type=int, default=200, help="reasoning models need room to think")
    args = parser.parse_args()

    missing = [v for v in ("SGP_API_KEY", "SGP_ACCOUNT_ID") if not os.getenv(v)]
    if missing:
        print(f"Export {', '.join(missing)} first.", file=sys.stderr)
        return 2

    config = get_config()
    if args.list:
        base = config.resolve_model_call("openai/probe").api_base
        list_models(base, config.get_model_headers(base))
        return 0
    if not args.model:
        parser.error("pass a model name, or --list")
    complete(args.model, args.max_tokens)
    return 0


if __name__ == "__main__":
    sys.exit(main())
