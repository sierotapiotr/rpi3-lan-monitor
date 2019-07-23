#!/usr/bin/env bash
docker run --name nginx_victim --mount type=bind,source=${PWD}/config,target=/etc/nginx/sites-enabled,readonly -p 80:80 -d nginx
