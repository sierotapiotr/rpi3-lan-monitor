#!/usr/bin/env bash
uwsgi --ini uwsgi_config.ini --chmod-socket=666 --py-autoreload 1