from flask import (
    request, session, Markup, abort
)
from time import time
import hmac
import os

CSRF_TOKEN_VALIDITY = 30*60 # half an hour, should be plenty

'''
a csrf token is 32 bytes long, available to user code only as 64 byte hex version

          1         2         3
012345678901234567890123456789012
[      data    ][     signat    ]
[  ts  ][ seid ]

ts = second-precise unix timestamp, as 8 byte big end integer
seid = session id, randomly generated 8 bytes (kept in session as hex (16 bytes))
data = ts || id
signat = first 16 bytes of sha256 hmac(data, key) with a secret key stored in config

on validation, data and hash are unpacked and verified, then ts and id are unpacked,
id gets verified with session storage, and ts is checked for expiration (CSRF_TOKEN_VALIDITY)

'''

class CSRF:
    def __init__(self, app):
        self.key = app.config['CSRF_SECRET']
        app.jinja_env.globals['generate_csrf'] = self.generate_csrf
        app.jinja_env.globals['generate_csrf_input'] = self.generate_csrf_input
        app.before_request(self.ensure_session_id)
    def ensure_session_id(self):
        seid = session.get('session_id')
        if not seid or len(seid) != 16:
            session['session_id'] = os.urandom(8).hex()
    def generate_csrf(self):
        ts = int(time()).to_bytes(8, 'big') # y2k38-s when 64 bits run out, should be fine
        seid = bytes.fromhex(session.get('session_id'))
        data = ts + seid # 16 bytes long
        signat = hmac.new(self.key, data, 'sha256').digest()[:16] # should be enough too i hope
        return (data+signat).hex() # 32 bytes total, 64 hexed
    def generate_csrf_input(self):
        csrf = self.generate_csrf()
        return Markup('<input type="hidden" name="_csrf" value="{}">'.format(csrf))
    def check(self, abort_on_fail=True):
        ok = self.verify_csrf_token(request.form.get('_csrf', ''))
        if not abort_on_fail:
            return ok
        if not ok:
            abort(400)
    def verify_csrf_token(self, token_str):
        if not token_str or len(token_str) != 64:
            return False
        try:
            token = bytes.fromhex(token_str)
            if len(token) != 32:
                return False
        except ValueError:
            return False
        data, signat = token[:16], token[16:]
        ts, seid = int.from_bytes(data[:8], 'big'), data[8:]
        # verify data first because slightly faster (no hash calc)
        correct_seid = bytes.fromhex(session.get('session_id'))
        if seid != correct_seid:
            return False
        correct_ts = int(time())
        if (correct_ts - ts) > CSRF_TOKEN_VALIDITY:
            return False
        correct_signat = hmac.new(self.key, data, 'sha256').digest()[:16]
        if not hmac.compare_digest(signat, correct_signat):
            return False
        return True
        
