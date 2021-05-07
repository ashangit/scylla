#!/usr/bin/env bash
deactivate
python3 -m venv --clear venv
source venv/bin/activate
pip3 install -r requirements.txt

echo "Start Rest Api Serevr"
uvicorn main:app --reload