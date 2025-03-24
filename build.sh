#!/usr/bin/env bash
# exit on error
set -o errexit

# Install Python if it doesn't exist
if ! command -v python3.9 &> /dev/null
then
    apt-get update
    apt-get install -y python3.9
fi

# Upgrade pip
python3.9 -m pip install --upgrade pip

# Install dependencies
pip install -r requirements.txt

# Make sure gunicorn is installed in the correct path
pip install gunicorn --user
