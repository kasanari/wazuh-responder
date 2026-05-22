from typing import NamedTuple


class ARRequest(NamedTuple):
    command: str
    arguments: tuple[str, ...]
    # custom: bool = False

    def __str__(self) -> str:
        return f'{self.command}({",".join(self.arguments)})'


class ActiveResponse(NamedTuple):
    agents: tuple[str, ...]
    description: str
    active_response_request: ARRequest

    def __str__(self) -> str:
        return (
            f'ActiveResponse(agents={self.agents}, '
            f'description="{self.description}", '
            f'active_response_request={self.active_response_request}'
        )


class WazuhAgent(NamedTuple):
    id: str
    name: str
    ip: str