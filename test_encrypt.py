import base64
import hashlib
import time
import unittest

import encrypt


def _replace_tag(xml, tag, new_value):
    start = xml.index(f"<{tag}")
    start = xml.index(">", start) + 1
    end = xml.index(f"</{tag}>")
    return xml[:start] + new_value + xml[end:]


class SpecStyleRoundTripTests(unittest.TestCase):
    def test_valid_request_gets_signed_yes(self):
        result = encrypt.run_demo_check()
        self.assertEqual(result["ret"], "y")
        self.assertTrue(result["response_verified"])
        self.assertIn("SHA-256 hash matches", result["steps"])

    def test_request_is_not_readable(self):
        request = encrypt.build_auth_request()
        self.assertNotIn(encrypt.DEMO_NAME, request)
        self.assertNotIn("<Pid", request)

    def test_every_request_uses_a_new_session_key(self):
        first = encrypt.build_auth_request(txn="t1")
        second = encrypt.build_auth_request(txn="t1")
        self.assertNotEqual(first, second)

    def test_changed_request_fails_signature_check_569(self):
        request = encrypt.build_auth_request().replace('rc="Y"', 'rc="N"')
        self.assertEqual(encrypt.process_auth(request)["err"], "569")

    def test_same_request_twice_is_refused_563(self):
        request = encrypt.build_auth_request()
        self.assertEqual(encrypt.process_auth(request)["ret"], "y")
        self.assertEqual(encrypt.process_auth(request)["err"], "563")

    def test_old_request_is_refused_561(self):
        old = time.time() - 48 * 3600
        request = encrypt.build_auth_request(now=old)
        self.assertEqual(encrypt.process_auth(request)["err"], "561")

    def test_future_request_is_refused_562(self):
        future = time.time() + 3600
        request = encrypt.build_auth_request(now=future)
        self.assertEqual(encrypt.process_auth(request)["err"], "562")

    def test_wrong_name_is_refused_100(self):
        request = encrypt.build_auth_request(name="Someone Else")
        self.assertEqual(encrypt.process_auth(request)["err"], "100")

    def test_unknown_number_is_refused_998(self):
        request = encrypt.build_auth_request(uid="111111111111")
        self.assertEqual(encrypt.process_auth(request)["err"], "998")

    def test_changed_pid_fails_decryption_502(self):
        request = encrypt.build_auth_request()
        data = base64.b64decode(request.split('type="X">')[1].split("</Data>")[0])
        broken = bytes([data[0] ^ 1]) + data[1:]
        tampered = _replace_tag(request, "Data", base64.b64encode(broken).decode())
        # Re-sign so only the encrypted data, not the signature, is wrong.
        unsigned = tampered.rpartition("<Signature>")[0]
        signature = encrypt._b64(encrypt._sign(encrypt._AUA_KEY, unsigned.encode()))
        resigned = f"{unsigned}<Signature>{signature}</Signature></Auth>"
        self.assertEqual(encrypt.process_auth(resigned)["err"], "502")

    def test_wrong_hash_fails_hmac_check_564(self):
        # Same session key and timestamp, but the hash belongs to a different PID.
        ts = encrypt.make_ts()
        pid = f'<Pid ts="{ts}" ver="2.0"><Demo><Pi name="Demo Customer"/></Demo></Pid>'.encode()
        key = encrypt.AESGCM.generate_key(bit_length=256)
        skey = encrypt._UIDAI_KEY.public_key().encrypt(key, encrypt.padding.PKCS1v15())
        unsigned = (
            f'<Auth uid="{encrypt.DEMO_UID}" rc="Y" tid="" ac="public" sa="public" ver="2.5" txn="x" lk="k">'
            f'<Skey ci="20300101">{encrypt._b64(skey)}</Skey>'
            f"<Hmac>{encrypt._b64(encrypt._gcm_encrypt(key, hashlib.sha256(b'other').digest(), ts))}</Hmac>"
            f'<Data type="X">{encrypt._b64(encrypt._gcm_encrypt(key, pid, ts))}</Data>'
        )
        signature = encrypt._b64(encrypt._sign(encrypt._AUA_KEY, unsigned.encode()))
        request = f"{unsigned}<Signature>{signature}</Signature></Auth>"
        self.assertEqual(encrypt.process_auth(request)["err"], "564")

    def test_forged_response_is_rejected(self):
        response = encrypt.run_demo_check()["xml"].replace('ret="y"', 'ret="n"')
        self.assertFalse(encrypt.verify_response(response))

    def test_garbage_input_is_refused_510(self):
        self.assertEqual(encrypt.process_auth("not xml")["err"], "510")


if __name__ == "__main__":
    unittest.main()
