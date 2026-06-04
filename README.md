# Readme

## Install

Either 

`uv tool install git+https://github.com/kasanari/wazuh-responder`

or

Clone the repo and run `uv tool install .`.

## How to run

List all agents

`wazuh-responder list`.

To shut down, run:
`wazuh-responder command --command shutdown --agent [AGENT NAME]`.

To isolate, run:
`wazuh-responder command --command isolate --agent [AGENT NAME]`.

## Web Interface

Run
`start_server.sh`
then go to `localhost:8000` in your web browser.

## Docker

Run `docker compose up`. Add the flag `-d` to run in the background. The server will use port 8000. Logs will be saved in a `logs/` directory created from the run location.
