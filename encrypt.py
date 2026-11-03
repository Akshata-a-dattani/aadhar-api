"""Spec-style simulation of one Aadhaar Authentication API round trip.

Everything here is fictional. Keys are generated in memory when the app starts,
the "UIDAI" below is a few lines of Python, and no network call is made. The
steps follow UIDAI Authentication API 2.5 (Rev 1) so they can be shown in class:

  * the PID block is encrypted with AES-256-GCM under a fresh session key
  * the session key is wrapped with RSA-2048 (RSA/ECB/PKCS1Padding)
  * "Hmac" is the SHA-256 of the PID, encrypted with the session key
  * the AUA signs the request and UIDAI signs the response (RSA-SHA256)
  * UIDAI rejects stale, future-dated, duplicate and tampered requests

Simplifications: the signature covers the request text directly instead of using
W3C XML-DSig, and the record store holds one fictional customer.
"""
import base64
import hashlib
import secrets
import time
from datetime import datetime, timedelta, timezone
from xml.etree import ElementTree as ET
from xml.sax.saxutils import quoteattr

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

IST = timezone(timedelta(hours=5, minutes=30))
TS_FORMAT = "%Y-%m-%dT%H:%M:%S"
TS_LEN = 19  # length of a timestamp such as 2026-11-03T11:40:00
MAX_AGE_SECONDS = 24 * 60 * 60  # spec: buffered requests up to 24 hours
MAX_FUTURE_SECONDS = 5 * 60  # demo threshold for "timestamp in the future"

DEMO_UID = "000000000000"
DEMO_NAME = "Demo Customer"
_RECORDS = {DEMO_UID: DEMO_NAME}  # stands in for CIDR

# Demo keys. They exist only in memory and are never written anywhere.
_UIDAI_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_AUA_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_seen_requests = set()  # duplicate detection (per process, demo only)


def _b64(data):
    return base64.b64encode(data).decode("ascii")


def make_ts(now=None):
    moment = time.time() if now is None else now
    return datetime.fromtimestamp(moment, IST).strftime(TS_FORMAT)


def _gcm_encrypt(key, data, ts):
    """Nonce = last 12 bytes of ts, AAD = last 16 bytes, tag appended, ts appended."""
    ts_bytes = ts.encode("ascii")
    return AESGCM(key).encrypt(ts_bytes[-12:], data, ts_bytes[-16:]) + ts_bytes


def _gcm_decrypt(key, blob):
    ciphertext, ts_bytes = blob[:-TS_LEN], blob[-TS_LEN:]
    data = AESGCM(key).decrypt(ts_bytes[-12:], ciphertext, ts_bytes[-16:])
    return data, ts_bytes.decode("ascii")


def _sign(private_key, data):
    return private_key.sign(data, padding.PKCS1v15(), hashes.SHA256())


def _verify(public_key, signature, data):
    try:
        public_key.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
        return True
    except InvalidSignature:
        return False


def build_auth_request(uid=DEMO_UID, name=DEMO_NAME, now=None, txn=None):
    """What the AUA server sends: Auth XML with Skey, Hmac, Data and Signature."""
    ts = make_ts(now)
    txn = txn or "demo-" + secrets.token_hex(8)
    pid = f'<Pid ts="{ts}" ver="2.0"><Demo><Pi name={quoteattr(name)}/></Demo></Pid>'.encode()

    session_key = AESGCM.generate_key(bit_length=256)  # fresh for every request
    skey = _UIDAI_KEY.public_key().encrypt(session_key, padding.PKCS1v15())
    data = _gcm_encrypt(session_key, pid, ts)
    hmac_value = _gcm_encrypt(session_key, hashlib.sha256(pid).digest(), ts)

    unsigned = (
        f'<Auth uid={quoteattr(uid)} rc="Y" tid="" ac="public" sa="public" ver="2.5" '
        f'txn={quoteattr(txn)} lk="demo-license-key">'
        '<Uses pi="y" pa="n" pfa="n" bio="n" bt="" pin="n" otp="n"/>'
        f'<Skey ci="20300101">{_b64(skey)}</Skey>'
        f"<Hmac>{_b64(hmac_value)}</Hmac>"
        f'<Data type="X">{_b64(data)}</Data>'
    )
    signature = _sign(_AUA_KEY, unsigned.encode())
    return f"{unsigned}<Signature>{_b64(signature)}</Signature></Auth>"


def _response(ret, txn, err, now, steps):
    attrs = f'ret="{ret}" code="{secrets.token_hex(8)}" txn={quoteattr(txn)} ts="{make_ts(now)}"'
    if err:
        attrs += f' err="{err}"'
    unsigned = f"<AuthRes {attrs}>"
    signature = _sign(_UIDAI_KEY, unsigned.encode())
    xml = f"{unsigned}<Signature>{_b64(signature)}</Signature></AuthRes>"
    return {"ret": ret, "err": err, "txn": txn, "xml": xml, "steps": list(steps)}


def process_auth(auth_xml, now=None):
    """The mock UIDAI: check the request step by step and answer yes or no."""
    now = time.time() if now is None else now
    steps = []
    txn = ""

    def fail(code):
        return _response("n", txn, code, now, steps)

    try:
        root = ET.fromstring(auth_xml)
        txn = root.get("txn", "")
        signature = base64.b64decode(root.findtext("Signature"))
        skey = base64.b64decode(root.findtext("Skey"))
        data = base64.b64decode(root.findtext("Data"))
        hmac_value = base64.b64decode(root.findtext("Hmac"))
    except (ET.ParseError, ValueError, TypeError):
        return fail("510")  # invalid Auth XML

    unsigned, separator, _ = auth_xml.rpartition("<Signature>")
    if not separator or not _verify(_AUA_KEY.public_key(), signature, unsigned.encode()):
        return fail("569")  # request changed after it was signed
    steps.append("AUA signature verified (RSA-SHA256)")

    try:
        session_key = _UIDAI_KEY.decrypt(skey, padding.PKCS1v15())
        if len(session_key) != 32:
            raise ValueError
    except ValueError:
        return fail("500")  # invalid session key
    steps.append("Session key unwrapped (RSA-2048)")

    try:
        pid, ts = _gcm_decrypt(session_key, data)
    except (InvalidTag, ValueError):
        return fail("502")  # invalid PID encryption
    steps.append("PID decrypted (AES-256-GCM)")

    try:
        sent_at = datetime.strptime(ts, TS_FORMAT).replace(tzinfo=IST).timestamp()
    except ValueError:
        return fail("511")  # invalid PID
    if now - sent_at > MAX_AGE_SECONDS:
        return fail("561")  # request expired
    if sent_at - now > MAX_FUTURE_SECONDS:
        return fail("562")  # timestamp in the future
    steps.append("Timestamp is fresh")

    fingerprint = hashlib.sha256(unsigned.encode()).hexdigest()
    if fingerprint in _seen_requests:
        return fail("563")  # duplicate request
    _seen_requests.add(fingerprint)
    steps.append("Not a repeat of an earlier request")

    try:
        sent_hash, _ = _gcm_decrypt(session_key, hmac_value)
    except (InvalidTag, ValueError):
        return fail("503")  # invalid Hmac encryption
    if not secrets.compare_digest(sent_hash, hashlib.sha256(pid).digest()):
        return fail("564")  # Hmac validation failed
    steps.append("SHA-256 hash matches")

    try:
        name = ET.fromstring(pid).find("./Demo/Pi").get("name", "")
    except (ET.ParseError, AttributeError):
        return fail("511")
    stored_name = _RECORDS.get(root.get("uid", ""))
    if stored_name is None:
        return fail("998")  # invalid Aadhaar number
    if name.casefold() != stored_name.casefold():
        return fail("100")  # basic details did not match
    steps.append("Record matched")

    return _response("y", txn, None, now, steps)


def verify_response(response_xml):
    """What the AUA does with UIDAI's answer: check the signature before trusting it."""
    unsigned, separator, rest = response_xml.rpartition("<Signature>")
    if not separator:
        return False
    try:
        signature = base64.b64decode(rest.split("</Signature>")[0])
    except ValueError:
        return False
    return _verify(_UIDAI_KEY.public_key(), signature, unsigned.encode())


def run_demo_check(now=None):
    """One full round trip for the fictional customer."""
    result = process_auth(build_auth_request(now=now), now=now)
    result["response_verified"] = verify_response(result["xml"])
    return result
