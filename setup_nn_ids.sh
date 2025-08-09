#!/bin/bash
# setup_nn_ids.sh - install dependencies and train neural network IDS
set -euo pipefail

pip3 install --no-input pandas scikit-learn joblib scapy

mkdir -p /opt/nnids/datasets
python3 /usr/local/bin/nn_ids_setup.py
python3 /usr/local/bin/nn_os_train.py
