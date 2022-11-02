from flask import request
import os
from redis import Redis

class FrameSession():
    def __init__(self, redisconn: Redis):
        self.r = redisconn
    def read(self):
        token = request.args.get('framesess', '')
        contents = self.r.get('ndk:framesess:'+token)
        if contents is None:
            token = None
        return token, contents
    def create(self, initial):
        assert initial is not None
        token = os.urandom(8).hex()
        self.r.set('ndk:framesess:'+token, initial, ex=30*60)
        return token
    def write(self, content):
        assert content is not None
        token, _ = self.read()
        if token is not None:
            self.r.set('ndk:framesess:'+token, content, ex=30*60)
