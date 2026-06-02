import json
import logging
from base64 import b64encode
from enum import Enum
from typing import NamedTuple

import requests
import urllib3

from .wazuh import ARRequest, WazuhResponse

logger = logging.getLogger(__name__)


def status_code_desc(http_status_code: int) -> str:
    return requests.status_codes._codes[http_status_code][0]  # type: ignore


class ResponderBehaviour(Enum):
    SEND_TO_WAZUH = "send"
    SKIP_SEND = "skip"


class WazuhRestServerConfig(NamedTuple):
    protocol: str
    host: str
    port: int
    user: str
    pwd: str


class Responder(NamedTuple):
    # The responder sends actions to wazuh

    user: str
    pwd: str
    base_url: str

    @classmethod
    def from_config(cls, config: WazuhRestServerConfig):
        user: str = config.user
        pwd: str = config.pwd

        base_url = f"{config.protocol}://{config.host}:{config.port}"

        # Disable insecure https warnings (for self-signed SSL certificates)
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        return cls(user=user, pwd=pwd, base_url=base_url)

    # The token times out after 10 minutes, so call this before every interaction.
    def get_header(self) -> dict[str, str] | None:
        logger.debug("Get authorization token header")
        login_endpoint = "security/user/authenticate"
        login_url = f"{self.base_url}/{login_endpoint}"
        basic_auth = f"{self.user}:{self.pwd}".encode()
        login_headers = {
            "Content-Type": "application/json",
            "Authorization": f"Basic {b64encode(basic_auth).decode()}",
        }

        try:
            response = requests.get(
                login_url, headers=login_headers, verify=False, timeout=5
            )
        except requests.exceptions.ConnectTimeout:
            logger.warning("Connection timed out while fetching token.")
            return None
        # This is the authorization token required.
        wazuh_token = json.loads(response.content.decode())["data"]["token"]
        return {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {wazuh_token}",
        }

    def print_agents(self):
        logger.debug("Agents:")
        response = requests.get(
            self.base_url + "/agents",
            headers=self.get_header(),
            verify=False,
            timeout=5,
        )
        status_code = response.status_code
        res_json = response.json()
        logger.debug(json.dumps(res_json, indent=4, sort_keys=True))
        logger.debug(
            f"Status: {status_code} - {status_code_desc(response.status_code)}"
        )

    def send_active_response_command(
        self, command: ARRequest, agents: tuple[str, ...], behaviour: ResponderBehaviour
    ):
        endpoint = f'/active-response?agents_list={",".join(agents)}&pretty=true'
        logger.debug(f'Send command: {command} to agent(s) {",".join(agents)}.')
        as_dict = {
            k: v for k, v in command._asdict().items() if v
        }  # Remove empty values
        json_data = json.dumps(as_dict)
        if behaviour == ResponderBehaviour.SKIP_SEND:
            return None

        header = self.get_header()
        if header is None:
            logger.warning(
                "Failed to get authorization token header, skipping sending active response command."
            )
            return None
        try:
            response: requests.Response = requests.put(
                url=self.base_url + endpoint,
                headers=header,
                verify=False,
                data=json_data,
                timeout=5,
            )
        except requests.exceptions.ConnectTimeout:
            logger.warning(
                "Connection timed out while sending active response command."
            )
            return None
        logger.debug(
            f"Got response code {response.status_code}: "
            f"{status_code_desc(response.status_code)}."
        )
        logger.debug(f"Got results:\n{json.dumps(response.json(), sort_keys=True)}")

        json_response = json.loads(response.json())

        wazuh_response = WazuhResponse(
            affected_items=tuple(json_response["data"]["affected_items"]),
            failed_items=tuple(json_response["data"]["failed_items"]),
            total_affected_items=json_response["data"]["total_affected_items"],
            total_failed_items=json_response["data"]["total_failed_items"],
            has_error=json_response["error"] == 1,
            message=json_response["message"],
        )
        return wazuh_response
