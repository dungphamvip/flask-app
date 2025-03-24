#!/usr/bin/env bash
# exit on error
set -o errexit

# Upgrade pip
python -m pip install --upgrade pip

# Install dependencies
pip install -r requirements.txt

# Install gunicorn
pip install gunicorn

# Make sure we're in the right directory
cd /opt/render/project/src
