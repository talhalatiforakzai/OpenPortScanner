#!/bin/sh
# this script is used to boot a Docker container
sleep 30

flask db upgrade
flask run --host 0.0.0.0