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
