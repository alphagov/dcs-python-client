#! /bin/bash
set -eou pipefail

pylint client
mypy client
