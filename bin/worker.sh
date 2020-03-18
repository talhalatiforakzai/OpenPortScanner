#!/bin/sh

sleep 20

celery -A app.celery.celery_app:celery worker --loglevel=info
