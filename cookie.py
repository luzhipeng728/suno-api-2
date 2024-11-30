import json
import os
import time
from http.cookies import SimpleCookie
import datetime
import requests

from utils import COMMON_HEADERS, notify, logger


class SunoCookie:
    def __init__(self):
        self.cookie = SimpleCookie()
        self.session_id = None
        self.token = None
        self.expire_at = None
        self.email = None
        self.check_token = None

    def load_cookie(self, cookie_str):
        self.cookie.load(cookie_str)

    def get_cookie(self):
        return ";".join([f"{i}={self.cookie.get(i).value}" for i in self.cookie.keys()])

    def set_session_id(self, session_id):
        self.session_id = session_id

    def get_session_id(self):
        return self.session_id

    def get_token(self):
        return self.token
    
    def check(self):
        """检查token是否有效"""
        try:
            headers = {
                'accept': '*/*',
                'accept-language': 'zh-CN,zh;q=0.9',
                'affiliate-id': 'undefined',
                'authorization': f'Bearer {self.check_token}',
                'content-type': 'text/plain;charset=UTF-8',
                'device-id': '"8c39237a-a1f5-415d-bcca-b017e3588dba"',
                'origin': 'https://suno.com',
                'priority': 'u=1, i',
                'referer': 'https://suno.com/',
                'sec-ch-ua': '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
                'sec-ch-ua-mobile': '?0',
                'sec-ch-ua-platform': '"macOS"',
                'sec-fetch-dest': 'empty',
                'sec-fetch-mode': 'cors',
                'sec-fetch-site': 'same-site',
                'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36'
            }
            
            response = requests.post(
                'https://studio-api.prod.suno.com/api/c/check',
                headers=headers,
                json={"ctype": "generation"},
                timeout=5
            )
            
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Token check failed: {e}")
            return False

    def set_token(self, token: str):
        self.token = token

    def set_expire_at(self, expire_at: int):
        self.expire_at = expire_at

    def get_expire_at(self):
        return self.expire_at

    def set_email(self, email: str):
        self.email = email

    def get_email(self):
        return self.email
    
    def set_check_token(self, check_token: bool):
        self.check_token = check_token

    def get_check_token(self):
        return self.check_token


clerk_js_version = "5.35.1"
CLERK_BASE_URL = (
    f"https://clerk.suno.com/v1/client?_clerk_js_version={clerk_js_version}"
)
suno_auth = SunoCookie()
suno_auth.load_cookie(os.getenv("COOKIE"))


def fetch_session_id(suno_cookie: SunoCookie):
    headers = {"cookie": suno_cookie.get_cookie()}
    headers.update(COMMON_HEADERS)
    resp = requests.get(CLERK_BASE_URL, headers=headers, timeout=5)
    session_id = resp.json().get("response").get("last_active_session_id")
    expire_at = resp.json().get("response").get("sessions")[0]["expire_at"]
    email = (
        resp.json()
        .get("response")
        .get("sessions")[0]["user"]
        .get("email_addresses")[0]
        .get("email_address")
    )
    email = f"{email.split('@')[0][:5]}****@{email.split('@')[1]}"
    suno_cookie.set_session_id(session_id)
    suno_cookie.set_expire_at(expire_at)
    suno_cookie.set_email(email)
    logger.info(
        f"{email} suno cookie will expire at {datetime.datetime.fromtimestamp(expire_at/1000).strftime('%Y-%m-%d %H:%M:%S')} session_id -> {session_id}"
    )


fetch_session_id(suno_auth)


def update_token(suno_cookie: SunoCookie):
    headers = {"cookie": suno_cookie.get_cookie()}
    headers.update(COMMON_HEADERS)
    session_id = suno_cookie.get_session_id()
    # print("=" * 100)
    # print(session_id)
    # print("=" * 100)
    url = f"https://clerk.suno.com/v1/client/sessions/{session_id}/touch?__clerk_api_version=2021-02-05&_clerk_js_version={clerk_js_version}"
    resp = requests.post(
        url=url,
        headers=headers,
        timeout=5,
    )

    resp_headers = dict(resp.headers)
    set_cookie = resp_headers.get("Set-Cookie")
    suno_cookie.load_cookie(set_cookie)
    token = resp.json()['response']["last_active_token"]["jwt"]
    if not token:
        logger.error(f"update token failed, response -> {resp.json()}")
        return
    suno_cookie.set_token(token)


def get_new_token(suno_cookie: SunoCookie):
    """获取新的token"""
    headers = {"cookie": suno_cookie.get_cookie()}
    headers.update(COMMON_HEADERS)
    session_id = suno_cookie.get_session_id()
    url = f"https://clerk.suno.com/v1/client/sessions/{session_id}/tokens?__clerk_api_version=2021-02-05&_clerk_js_version={clerk_js_version}"
    
    try:
        resp = requests.post(
            url=url,
            headers=headers,
            data="organization_id=",
            timeout=5
        )
        # print("=" * 100)
        # print(resp.text)
        # print("=" * 100)
        token = resp.json()['jwt']
        if token:
            suno_cookie.set_check_token(True)
            logger.info(f"Successfully refreshed token for {suno_cookie.get_email()}")
            return True
    except Exception as e:
        logger.error(f"Failed to get new token: {e}")
        return False


def keep_alive(suno_cookie: SunoCookie):
    interval = suno_cookie.get_expire_at() - int(time.time() * 1000)
    if interval < 0:
        notify(
            f"email: {suno_cookie.get_email()} suno cookie has expired at {datetime.datetime.fromtimestamp(suno_cookie.get_expire_at()/1000).strftime('%Y-%m-%d %H:%M:%S')}, please update"
        )
    elif interval < 60 * 60 * 24 * 1000:
        notify(
            f"email: {suno_cookie.get_email()} suno cookie will expire at {datetime.datetime.fromtimestamp(suno_cookie.get_expire_at()/1000).strftime('%Y-%m-%d %H:%M:%S')}, please update"
        )
    try:
        update_token(suno_cookie)
    except Exception as e:
        logger.error(
            f"{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} *** keep_alive error -> {e} ***"
        )