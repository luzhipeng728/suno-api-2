from cookie import suno_auth, keep_alive
from cookie import update_token


def get_token():
    keep_alive(suno_auth)
    token = suno_auth.get_token()
    yield token

def get_token_new():
    keep_alive(suno_auth)
    suno_auth.check()
    token = suno_auth.get_token()
    yield token
