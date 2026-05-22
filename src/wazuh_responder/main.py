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

# curl "https://134.24.17.90:55000/agents?pretty=true&sort=-ip,name" -k --cacert certs/tyr_demo3_root-ca.pem -H "Authorization: Bearer $(cat token.txt)"


"""
{
            "os": {
               "arch": "x86_64",
               "codename": "Jammy Jellyfish",
               "major": "22",
               "minor": "04",
               "name": "Ubuntu",
               "platform": "ubuntu",
               "uname": "Linux |snort-srv |5.15.0-58-generic |#64-Ubuntu SMP Thu Jan 5 11:43:13 UTC 2023 |x86_64",
               "version": "22.04.1 LTS"
            },
            "lastKeepAlive": "2026-05-22T09:38:04+00:00",
            "id": "005",
            "status_code": 0,
            "configSum": "ab73af41699f13fdd81903b5f23d8d00",
            "manager": "wazuh",
            "name": "snort-srv",
            "ip": "134.24.17.133",
            "group": [
               "default"
            ],
            "node_name": "node01",
            "mergedSum": "672c2dd4c55689631f945a884f144dd2",
            "status": "active",
            "version": "Wazuh v4.3.2",
            "registerIP": "any",
            "dateAdd": "2026-03-13T17:24:06+00:00",
            "group_config_status": "synced"
         },

"""


class Destination(Enum):
    WAZUH = "wazuh"
    STDOUT = "stdout"


class Config(NamedTuple):
    command: Literal["shutdown", "isolate"]
    agent: str
    agent_file: str | None = None
    destination = Destination.WAZUH


def agents_from_dict(agent_dict: dict[str, Any]) -> WazuhAgent:
    return WazuhAgent(
        id=agent_dict["id"],
        name=agent_dict["name"],
        ip=agent_dict["ip"],
    )


def main(config: Config):
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

    try:
        target_agent = agents[agent]
    except KeyError:
        raise ValueError(f"Target agent '{agent}' not found in Wazuh manager")

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


def cli():
    config = tyro.cli(Config)
    main(config)


if __name__ == "__main__":
    cli()
