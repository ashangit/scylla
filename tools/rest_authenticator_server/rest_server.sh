#!/usr/bin/env bash
deactivate
python3 -m venv --clear venv
source venv/bin/activate
pip3 install -r requirements.txt

echo "Start Rest Api Serevr"
uvicorn main:app --ssl-keyfile ssl/rest_api.key --ssl-certfile ssl/rest_api.crt