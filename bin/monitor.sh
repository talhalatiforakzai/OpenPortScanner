#!/bin/sh

sleep 30

flower -A app.celery.celery_app:celery --port=5555 --broker=redis://redis:6379/0