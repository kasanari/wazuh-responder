# flask app to send active response commands to wazuh manager
from flask import Flask, render_template, request
from wazuh_responder.responder import (
    Responder,
    WazuhRestServerConfig,
    ResponderBehaviour,
)
from wazuh_responder.main import (
    get_agents,
    FIREWALL_AGENT_NAME,
    command_to_action,
    agents_from_dict,
)
import requests
import json

DEBUG = True

agents = (
    get_agents()
    if not DEBUG
    else {
        agent["name"]: agents_from_dict(agent)
        for agent in json.load(open("test/agents.json"))
    }
)

if agents is None:
    raise ValueError("No agents found in Wazuh manager")

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


app = Flask(__name__)

print("Starting Wazuh Responder Flask app...")
print("Available agents:")
for agent in agents.values():
    print(f"- {agent.name} (ID: {agent.id}, IP: {agent.ip})")



@app.route("/", methods=["GET"])
def index():
    return render_template(
        "action_form.html",
        agents=agents.values(),
        actions=[
            "isolate",
            "shutdown",
        ],
    )


@app.route("/send_command", methods=["GET"])
def send_command_get():
    return render_template("status_box.html", message="This endpoint only accepts POST requests"), 405

@app.route("/send_command", methods=["POST"])
def send_command():
    agent_name = request.form["agents"]
    command = request.form["actions"]
    print(f"Received command: {command} for agent: {agent_name}")

    if not agent_name or not command:
        return render_template("status_box.html", message="Agent name and command are required"), 400

    target_agent = agents.get(agent_name)
    if not target_agent:
        return render_template("status_box.html", message=f"Agent '{agent_name}' not found"), 404

    action = command_to_action(command, target_agent, firewall_agent_id)

    result = responder.send_active_response_command(
        action.active_response_request,
        agents=(target_agent.id,),
        behaviour=ResponderBehaviour.SKIP_SEND,
    )

    if isinstance(result, requests.Response):
        return render_template("status_box.html", message="Command sent to Wazuh manager"), 200
    else:
        return render_template("status_box.html", message="Command processed without sending to Wazuh manager"), 200
