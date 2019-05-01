#!/usr/bin/env bash
uwsgi --ini uwsgi_config.ini --chmod-socket=666 --plugin python36 -s :0