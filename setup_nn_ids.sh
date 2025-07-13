#!/bin/bash
# setup_nn_ids.sh - install dependencies and train neural network IDS
set -euo pipefail

pip3 install --no-input pandas scikit-learn joblib

python3 /usr/local/bin/nn_ids_setup.py
