from cookie import suno_auth, keep_alive
from cookie import update_token


def get_token():
    keep_alive(suno_auth)
    update_token(suno_auth)
    token = suno_auth.get_token()
    print("get token", token)
    yield token
