from enum import Enum
from logging import warning
import logging
from typing import Any, NamedTuple
import datetime
from typing import Literal
import requests

from .responder import Responder, ResponderBehaviour, WazuhRestServerConfig

from .wazuh import WazuhAgent
from .actions import command_to_action
import tyro
import json

FIREWALL_AGENT_NAME = "fw1"
AUTH_ENDPOINT = "https://134.24.17.90:55000/security/user/authenticate"
AGENT_ENDPOINT = "https://134.24.17.90:55000/agents"

WAZUH_CONF = {}
logger = logging.getLogger(__name__)
persist_logger = logging.getLogger("persist")


class Destination(Enum):
    WAZUH = "wazuh"
    STDOUT = "stdout"

class List(NamedTuple):
    """List all agents in Wazuh manager"""

    pass


class Command(NamedTuple):
    """Issue a command to an agent"""
    command: Literal["shutdown", "isolate"]  # command to execute on the agent
    agent: str  # name of the target agent in Wazuh manager
    agent_id: str | None = (
        None  # optional agent ID, if not provided, it will be fetched from Wazuh manager using the agent name
    )
    agent_file: str | None = (
        None  # optional path to a JSON file containing agent information, if not provided, agents will be fetched from Wazuh manager
    )
    destination = (
        Destination.WAZUH
    )  # where to send the command, either to Wazuh manager or just print it to stdout


def agents_from_dict(agent_dict: dict[str, Any]) -> WazuhAgent:
    return WazuhAgent(
        id=agent_dict["id"],
        name=agent_dict["name"],
        ip=agent_dict["ip"],
    )


def main(config: Command):
    current_time = datetime.datetime.now()
    logger.setLevel(logging.INFO)
    logger.addHandler(logging.StreamHandler())
    persist_logger.addHandler(
        logging.FileHandler(f"responder_{current_time.strftime('%Y%m%d')}.log")
    )
    persist_logger.setLevel(logging.INFO)
    agents = (
        get_agents()
        if not config.agent_file
        else {
            agent["name"]: agents_from_dict(agent)
            for agent in json.load(open(config.agent_file))
        }
    )
    if agents is None:
        return

    responder = Responder.from_config(
        WazuhRestServerConfig(
            protocol="https", host="134.24.17.90", port=55000, user="wazuh", pwd="wazuh"
        )
    )

    try:
        firewall_agent_id = agents[FIREWALL_AGENT_NAME].id
    except KeyError:
        raise ValueError(
            f"Firewall agent '{FIREWALL_AGENT_NAME}' not found in Wazuh manager"
        )

    command = config.command
    agent = config.agent

    if config.agent_id is not None:
        # If agent ID is provided, find the agent by ID
        target_agent = next(
            (agent for agent in agents.values() if agent.id == config.agent_id), None
        )
        if target_agent is None:
            raise ValueError(
                f"Target agent with ID '{config.agent_id}' not found in Wazuh manager"
            )
    else:
        try:
            target_agent = agents[agent]
        except KeyError:
            raise ValueError(f"Agent with name '{agent}' not found in Wazuh manager")

    action = command_to_action(command, target_agent, firewall_agent_id)

    destinations = {
        Destination.WAZUH: lambda: responder.send_active_response_command(
            action.active_response_request,
            agents=(target_agent.id,),
            behaviour=ResponderBehaviour.SEND_TO_WAZUH,
        ),
        Destination.STDOUT: lambda: responder.send_active_response_command(
            action.active_response_request,
            agents=(target_agent.id,),
            behaviour=ResponderBehaviour.SKIP_SEND,
        ),
    }

    result = destinations[config.destination]()

    if isinstance(result, requests.Response):
        success = result.status_code == 200
    elif result is None:
        success = False
    else:
        raise ValueError(f"Unexpected result type: {type(result)}")

    persist_logger.info(
        ",".join(
            [f"{command}", f"{agent}", f"{current_time.isoformat()}", f"{success}"]
        )
    )
    logger.warning(
        f"Tried to execute command '{command}' on agent '{agent}'. Success: {success}."
    )


def get_agents() -> dict[str, WazuhAgent] | None:
    """
    curl "https://134.24.17.90:55000/security/user/authenticate" -u "wazuh:wazuh" -k
    """

    # get token
    login_url = "https://134.24.17.90:55000/security/user/authenticate"
    logger.warning("Fetching token.")
    try:
        response = requests.get(
            login_url, auth=("wazuh", "wazuh"), verify=False, timeout=5
        )
    except requests.exceptions.ConnectTimeout:
        logger.warning("Connection timed out while fetching token.")
        return None
    token = response.json()["data"]["token"]

    # get agents
    warning("Fetching agents.")
    try:
        response = requests.get(
            AGENT_ENDPOINT,
            headers={"Authorization": f"Bearer {token}"},
            verify=False,
            params={"sort": "-ip,name"},
        )
    except requests.exceptions.ConnectTimeout:
        warning("Connection timed out while fetching agents.")
        return None
    agents = response.json()["data"]["affected_items"]

    return {agent["name"]: agents_from_dict(agent) for agent in agents}

def list_agents():
    agents = get_agents()
    if agents is None:
        return

    print("Name, ID, IP")
    for agent in agents.values():
        print(f"{agent.name}, {agent.id}, {agent.ip}")

def cli():
    config = tyro.cli(Command | List)
    if isinstance(config, List):
        list_agents()
    else:
        main(config)


if __name__ == "__main__":
    cli()
