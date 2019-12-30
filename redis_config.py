#!/usr/bin/env python
# coding=utf-8

# import redis

HOST = 'localhost'
PORT = 6379
DB = 0
# PW = 'fw@redis'
# if redis password not set
PW = None

SUB_CHANNEL = 'netlog_*'

__all__ = ['HOST', 'PORT', 'DB', 'SUB_CHANNEL', 'PW']

