#!/usr/bin/python
# -*- coding: utf-8 -*-
blob = """
           Z���ԺW�#�_�"���5��Z�Q�y�u2������_�?��-�Q��Z)��]W���� �d�9w�	��*e
�;�x�ifq|_1b�.��Z�H��~f�����Q�?h���#f������b�뽋"""
from hashlib import sha256
if int(sha256(blob).hexdigest(), 16) % 2: print 'I mean no harm.'
else: print 'You are doomed!'


