import unittest

from streamlit.testing.v1 import AppTest


class TestStreamlitApp(unittest.TestCase):

    def test_app_starts_with_both_scanners(self):
        app = AppTest.from_file("app.py").run(timeout=30)

        self.assertFalse(app.exception)
        self.assertEqual(len(app.tabs), 2)


if __name__ == "__main__":
    unittest.main()
