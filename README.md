# Readme

## Install

Either 

`uv tool install git+https://github.com/kasanari/wazuh-responder`

or

Clone the repo and run `uv tool install .`.

## How to run

To shut down, run:
`wazuh-responder --command shutdown --agent [AGENT NAME]`.

To isolate, run:
`wazuh-responder --command isolate --agent [AGENT NAME]`.
