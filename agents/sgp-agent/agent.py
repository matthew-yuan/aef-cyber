"""sgp-agent: a tool-using A2A agent that calls models on Scale GenAI Platform (SGP).

One image serves every role in the SOC eval (analyst, and any judge or reporter agent): the task gives
each deployment its role, system prompt and model. It works the tools of every env it is handed,
over MCP, and calls the model through SGP's OpenAI-compatible endpoint.

agent-env hands it the endpoint as env vars: LITELLM_BASE_URL, LITELLM_API_KEY and
LITELLM_EXTRA_HEADERS (a JSON object; for SGP, x-api-key and x-selected-account-id).
"""
import json
import os
from contextlib import AsyncExitStack

from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client
from openai import AsyncOpenAI

from agentenv_protocol.a2a_agent import (
    MCP_CONFIG_V1,
    TRAJECTORY_V1,
    AgentConfig,
    AgentEnvAgent,
    AgentIdentity,
    TaskRequest,
    TaskResult,
    TextPart,
    Usage,
    a2a_agent,
)

# Every A2A context is one conversation, so a later turn continues where the last one ended.
CONVERSATIONS: dict[str, list] = {}


def sgp_model_name(model: str) -> str:
    """SGP names models provider/model ("openai/gpt-4o"). agent-env's config holds LiteLLM names, which
    add a routing prefix ("openai/openai/gpt-4o"); drop it so this client sends SGP's own name."""
    head, _, rest = model.partition("/")
    return rest if head == "openai" and "/" in rest else model


def model_client() -> AsyncOpenAI:
    headers = json.loads(os.environ.get("LITELLM_EXTRA_HEADERS") or "{}")
    return AsyncOpenAI(
        base_url=os.environ["LITELLM_BASE_URL"],
        api_key=os.environ["LITELLM_API_KEY"],
        default_headers=headers,
        timeout=300,
    )


class SGPAgentConfig(AgentConfig):
    model: str = "openai/gpt-4o"
    system_prompt: str = "You work in the systems you are given. Use their tools and say what you did."
    max_turns: int = 40
    max_tokens: int = 8000


@a2a_agent(
    identity=AgentIdentity(
        name="sgp-agent",
        description="A model on SGP that works the tools of the envs it is given, across the turns of a conversation.",
        version="1.0.0",
    ),
    config=SGPAgentConfig,
    extensions=(MCP_CONFIG_V1, TRAJECTORY_V1),
)
class SGPAgent(AgentEnvAgent):
    async def run(self, request: TaskRequest[SGPAgentConfig]) -> TaskResult:
        config = request.config
        client = model_client()
        model = sgp_model_name(config.model)
        message = "\n".join(part.text for part in request.parts if isinstance(part, TextPart))
        messages = CONVERSATIONS.setdefault(request.context_id, [{"role": "system", "content": config.system_prompt}])
        messages.append({"role": "user", "content": message})
        # This turn's trajectory: the message, each model call's text, each tool call with its result, and the answer.
        turn: list[dict] = [{"type": "message", "text": message, "model": model}]
        prompt_tokens = completion_tokens = 0

        async with AsyncExitStack() as stack:
            sessions, tools = {}, []
            for server in request.mcp_servers.values():
                read, write, _ = await stack.enter_async_context(
                    streamablehttp_client(server["url"], headers=server.get("headers"))
                )
                session = await stack.enter_async_context(ClientSession(read, write))
                await session.initialize()
                for tool in (await session.list_tools()).tools:
                    sessions[tool.name] = session
                    tools.append({"type": "function", "function": {
                        "name": tool.name, "description": tool.description or "", "parameters": tool.inputSchema,
                    }})

            for _ in range(config.max_turns):
                response = await client.chat.completions.create(
                    model=model,
                    messages=messages,
                    tools=tools or None,
                    max_tokens=config.max_tokens,
                )
                if response.usage:
                    prompt_tokens += response.usage.prompt_tokens or 0
                    completion_tokens += response.usage.completion_tokens or 0
                choice = response.choices[0]
                reply = choice.message
                calls = reply.tool_calls or []
                messages.append({
                    "role": "assistant",
                    "content": reply.content,
                    **({"tool_calls": [c.model_dump(exclude_none=True) for c in calls]} if calls else {}),
                })
                if reply.content and calls:
                    turn.append({"type": "thought", "text": reply.content})
                if not calls:
                    answer = reply.content or ""
                    turn.append({"type": "answer", "text": answer, "finish_reason": choice.finish_reason})
                    return (
                        TaskResult.builder()
                        .succeeded()
                        .add_text(answer)
                        .usage(Usage(
                            tool_call_count=sum(step["type"] == "tool_call" for step in turn),
                            input_tokens=prompt_tokens,
                            output_tokens=completion_tokens,
                        ))
                        .native_trajectory(format="sgp-agent/v1", payload=turn)
                        .build()
                    )
                for call in calls:
                    name = call.function.name
                    try:
                        args = json.loads(call.function.arguments or "{}")
                    except json.JSONDecodeError as exc:
                        output, args = f"error: arguments are not valid JSON ({exc})", call.function.arguments
                    else:
                        if name not in sessions:
                            output = f"error: no tool named {name}"
                        else:
                            result = await sessions[name].call_tool(name, args)
                            output = "\n".join(c.text for c in result.content if c.type == "text")
                    turn.append({"type": "tool_call", "tool": name, "input": args, "output": output})
                    messages.append({"role": "tool", "tool_call_id": call.id, "content": output})

        return TaskResult.failure("max_turns", f"Still calling tools after {config.max_turns} model calls")


if __name__ == "__main__":
    SGPAgent().serve()
