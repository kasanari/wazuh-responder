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
            f"ActiveResponse(agents={self.agents}, "
            f'description="{self.description}", '
            f"active_response_request={self.active_response_request}"
        )


class WazuhAgent(NamedTuple):
    id: str
    name: str
    ip: str


class WazuhResponse(NamedTuple):
    """
    "data": {"affected_items": ["015"], "failed_items": [], "total_affected_items": 1,
    "total_failed_items": 0}, "error": 0, "message": "AR command was sent to all agents"}
    """

    affected_items: tuple[str, ...]
    failed_items: tuple[str, ...]
    total_affected_items: int
    total_failed_items: int
    has_error: bool
    message: str
