from base64 import b64encode
from hmac import HMAC
from urllib.parse import urlencode
from hashlib import sha256
from termcolor import colored

from configuration import client_secret


def create_vk_query(query):
    vk_subset = sorted(
        filter(
            lambda key: key.startswith("vk_"),
            query
        )
    )
    ordered = {k: query[k] for k in vk_subset}
    return urlencode(ordered, doseq=True) + "&sign=" + query['sign']


def check_vk_sign(query, uid):
    query['vk_user_id'] = uid

    if not query.get("sign"):
        return False

    vk_subset = sorted(
        filter(
            lambda key: key.startswith("vk_"),
            query
        )
    )

    if not vk_subset:
        return False

    ordered = {k: query[k] for k in vk_subset}
    hash_code = b64encode(
        HMAC(
            client_secret.encode(),
            urlencode(ordered, doseq=True).encode(),
            sha256
        ).digest()
    ).decode("utf-8")

    if hash_code[-1] == "=":
        hash_code = hash_code[:-1]

    fixed_hash = hash_code.replace('+', '-').replace('/', '_')
    return query.get("sign") == fixed_hash
