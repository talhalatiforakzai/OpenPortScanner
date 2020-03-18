#!/bin/sh
# this script is used to boot a Docker container
sleep 10

flask db init
flask db migrate
flask db upgrade
gunicorn --bind 0.0.0.0:5001 --workers 4 ops:my_app

#celery -A app.celery.celery_app.celery worker --loglevel=info
