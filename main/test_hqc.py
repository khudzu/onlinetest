import json
import unittest

from django.test import SimpleTestCase, override_settings

from main.crypto.aes_hqc import generate_hqc_keypair, wrap_aes_key, wrap_aes_key_double
from main.crypto.aes_reed_muller import unwrap_aes_key


try:
    import oqs

    HQC_AVAILABLE = "HQC-1" in oqs.get_enabled_kem_mechanisms()
except ImportError:
    HQC_AVAILABLE = False


@unittest.skipUnless(HQC_AVAILABLE, "liboqs with HQC-1 is not enabled")
class HqcEnvelopeTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.keys = generate_hqc_keypair()

    def test_single_envelope_round_trip(self):
        with override_settings(**self.keys):
            dek = b"test AES DEK, 32 bytes long......."[:32]
            envelope = wrap_aes_key(dek, label="A")
            self.assertEqual(unwrap_aes_key(json.dumps(envelope)), dek)

    def test_repeated_double_wrap_round_trip(self):
        with override_settings(**self.keys):
            dek = b"0123456789abcdef0123456789abcdef"
            payload = wrap_aes_key_double(dek, repetitions=2)
            self.assertEqual(unwrap_aes_key(payload), dek)

    def test_corrupt_copy_is_ignored_when_other_copies_survive(self):
        with override_settings(**self.keys):
            dek = b"0123456789abcdef0123456789abcdef"
            payload = json.loads(wrap_aes_key_double(dek, repetitions=2))
            payload["wrapped_DEK_A_1"]["wrapped_dek"] = "AAAA"
            self.assertEqual(unwrap_aes_key(json.dumps(payload)), dek)
