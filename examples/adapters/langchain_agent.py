"""Adapter template: put a LangChain agent behind the Gauntlet contract.

Replace `build_agent()` with your real chain/AgentExecutor. The file runs as-is
(with a safe echo fallback) so you can wire the plumbing first, then drop your
agent in. No LangChain dependency is required to run this template.

    python langchain_agent.py            # serves :8000
    gauntlet run --target http://localhost:8000 --multiturn --canaries canaries.json
"""

from serve import serve


def build_agent():
    """Return a callable `agent(message: str, history: list) -> str`.

    Swap the body for your LangChain setup, e.g.:

        from langchain.agents import AgentExecutor
        executor = AgentExecutor(...)
        def agent(message, history):
            # map Gauntlet's {role, content} history to LangChain messages if needed
            return executor.invoke({"input": message})["output"]
        return agent
    """
    def agent(message, history):
        # --- replace this fallback with your real agent call ---
        return ("[demo] I'd help with your order — but this is the template's echo. "
                "Wire build_agent() to your LangChain AgentExecutor.")
    return agent


def main():
    agent = build_agent()

    def reply(message, history):
        # history is a list of {"role": "user"/"assistant", "content": ...} when
        # Gauntlet is run with --history-field messages (for --multiturn).
        return agent(message, history)

    serve(reply, port=8000)


if __name__ == "__main__":
    main()
