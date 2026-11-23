from unittest.mock import patch

from django.test import LiveServerTestCase, TestCase, tag
from django.urls import reverse
from selenium import webdriver

from main.crypto.mceliece_reed_muller import (
    decrypt_bits,
    decrypt_bytes,
    encrypt_bits,
    encrypt_bytes,
    generate_keypair,
)
from main.crypto.aes_reed_muller import (
    decrypt_image_bytes,
    decrypt_text,
    encrypt_image_bytes,
    encrypt_text,
    generate_aes_key,
    unwrap_aes_key,
    unwrap_aes_key_double,
    wrap_aes_key,
    wrap_aes_key_double,
)


@tag('functional')
class FunctionalTestCase(LiveServerTestCase):
    """Base class for functional test cases with selenium."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        # Change to another webdriver if desired (and update CI accordingly).
        options = webdriver.chrome.options.Options()
        # These options are needed for CI with Chromium.
        options.headless = True  # Disable GUI.
        options.add_argument('--no-sandbox')
        options.add_argument('--disable-dev-shm-usage')
        cls.selenium = webdriver.Chrome(options=options)

    @classmethod
    def tearDownClass(cls):
        cls.selenium.quit()
        super().tearDownClass()


class MainTestCase(TestCase):
    def test_root_url_status_200(self):
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        response = self.client.get(reverse('main:home'))
        self.assertEqual(response.status_code, 200)


class HQCBenchmarkHelpersTestCase(TestCase):
    @patch("main.benchmark.unwrap_hqc_key")
    @patch("main.benchmark.wrap_hqc_key")
    def test_single_and_double_repeated_envelopes_round_trip(self, wrap, unwrap):
        from main.benchmark import _unwrap_hqc, _wrap_hqc

        dek = b"test-dek"
        wrap.side_effect = lambda key, label: {"dek": key.decode(), "label": label}
        unwrap.side_effect = lambda artifact, label: artifact["dek"].encode()

        for wrapping, repetition in (("single", 1), ("single", 3), ("double", 1), ("double", 3)):
            with self.subTest(wrapping=wrapping, repetition=repetition):
                payload = _wrap_hqc(dek, wrapping, repetition)
                self.assertEqual(_unwrap_hqc(payload), dek)

    def test_factorial_effects_are_calculated_within_blocks(self):
        from main.benchmark import CONFIGURATIONS, _paired_factor_tests

        values = {
            "T1_single_no_repetition": [0.0, 0.0, 0.0],
            "T2_single_repetition_3": [2.0, 2.0, 2.0],
            "T3_double_no_repetition": [4.0, 4.0, 4.0],
            "T4_double_repetition_3": [8.0, 8.0, 8.0],
        }
        results = [
            {
                "configuration": name,
                "metric": {"observations_ms": values[name]},
            }
            for name, _, _ in CONFIGURATIONS
        ]

        effects = _paired_factor_tests(results, "metric")

        self.assertEqual(effects["repetition_main_effect"]["mean_effect_ms"], 3.0)
        self.assertEqual(effects["double_wrap_main_effect"]["mean_effect_ms"], 5.0)
        self.assertEqual(effects["interaction"]["mean_effect_ms"], 2.0)
        self.assertEqual(effects["interaction"]["n_independent_blocks"], 3)

    def test_holm_adjustment_controls_familywise_order(self):
        from main.benchmark import _holm_adjust

        adjusted = _holm_adjust({"a": 0.01, "b": 0.04, "c": 0.03})

        self.assertAlmostEqual(adjusted["a"], 0.03)
        self.assertAlmostEqual(adjusted["c"], 0.06)
        self.assertAlmostEqual(adjusted["b"], 0.06)

    def test_dummy_image_is_512_rgb_png(self):
        from io import BytesIO

        from PIL import Image

        from main.benchmark import build_dummy_image

        image = Image.open(BytesIO(build_dummy_image(4)))

        self.assertEqual(image.format, "PNG")
        self.assertEqual(image.mode, "RGB")
        self.assertEqual(image.size, (512, 512))


class McElieceReedMullerTestCase(TestCase):
    def test_bit_round_trip(self):
        public_key, private_key = generate_keypair(order_m=4, seed=7)
        message = [1, 0, 1, 1, 0]

        ciphertext = encrypt_bits(message, public_key, seed=11)
        plaintext = decrypt_bits(ciphertext, private_key)

        self.assertEqual(plaintext.tolist(), message)

    def test_byte_round_trip(self):
        public_key, private_key = generate_keypair(order_m=4, seed=13)
        message = b"halo"

        ciphertext_blocks, padding = encrypt_bytes(message, public_key, seed=17)
        plaintext = decrypt_bytes(ciphertext_blocks, private_key, padding)

        self.assertEqual(plaintext, message)

    def test_aes_key_wrap_and_text_round_trip(self):
        aes_key = generate_aes_key()
        wrapped_key = wrap_aes_key(aes_key)
        unwrapped_key = unwrap_aes_key(wrapped_key)

        ciphertext = encrypt_text("rahasia", aes_key)
        plaintext = decrypt_text(ciphertext, unwrapped_key)

        self.assertEqual(unwrapped_key, aes_key)
        self.assertEqual(plaintext, "rahasia")

    def test_password_wrapped_aes_key_round_trip(self):
        aes_key = generate_aes_key()
        salt = "MDEyMzQ1Njc4OWFiY2RlZg=="

        wrapped_key = wrap_aes_key(aes_key, "kunci-user", salt)
        unwrapped_key = unwrap_aes_key(wrapped_key, "kunci-user", salt)

        self.assertEqual(unwrapped_key, aes_key)

    def test_double_wrapped_aes_key_round_trip(self):
        aes_key = generate_aes_key()

        wrapped_key = wrap_aes_key_double(aes_key)
        unwrapped_key = unwrap_aes_key_double(wrapped_key)

        self.assertEqual(unwrapped_key, aes_key)

    def test_aes_image_round_trip(self):
        aes_key = generate_aes_key()
        image_bytes = b"fake-image-bytes"

        ciphertext = encrypt_image_bytes(image_bytes, aes_key)
        plaintext = decrypt_image_bytes(ciphertext, aes_key)

        self.assertEqual(plaintext, image_bytes)


class MainFunctionalTestCase(FunctionalTestCase):
    def test_root_url_exists(self):
        self.selenium.get(f'{self.live_server_url}/')
        html = self.selenium.find_element_by_tag_name('html')
        self.assertNotIn('not found', html.text.lower())
        self.assertNotIn('error', html.text.lower())
