from .wazuh import ARRequest

from .wazuh import WazuhAgent
from .wazuh import ActiveResponse


def isolate_agent(agent: WazuhAgent, fw_agent_id: str) -> ActiveResponse:
    return ActiveResponse(
        (fw_agent_id,),
        "Isolate machine",
        active_response_request=ARRequest(
            command="block_ip_address0",
            arguments=(agent.ip,),
        ),
    )


def shutdown_agent(agents: tuple[WazuhAgent]) -> ActiveResponse:
    return ActiveResponse(
        agents=tuple(a.id for a in agents),
        description="Shutdown machine",
        active_response_request=ARRequest(
            command="shutdown_machine0",
            arguments=(),
        ),
    )


def command_to_action(command: str, agent: WazuhAgent, fw_agent_id: str) -> ActiveResponse:
	if command == "isolate":
		return isolate_agent(agent, fw_agent_id)
	elif command == "shutdown":
		return shutdown_agent((agent,))
	else:
		raise ValueError(f"Unknown command '{command}'")