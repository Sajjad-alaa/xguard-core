#!/bin/sh
CONFIG=/etc/xguard/core.conf

if [ ! -f "${CONFIG}" ]; then
    cp "${CONFIG}.sample" "${CONFIG}"
fi
