#!/usr/bin/env bash
./run.sh
uwsgi --ini uwsgi_config.ini --chmod-socket=666
