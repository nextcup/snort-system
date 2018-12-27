#!/bin/bash

systemctl stop firewalld.service
systemctl start nginx.service
chmod +x ./tool/*
source ./tool/config.sh
uwsgi --socket mysite.sock --modul snort.wsgi --chmod-socket=666 --enable-threads
