import unittest
from unittest.mock import patch

import terminal_pressure


class TerminalPressureCliTests(unittest.TestCase):
    def test_stress_command_does_not_import_optional_modules(self):
        with patch("terminal_pressure._load_optional_dependency", side_effect=AssertionError("unexpected import")), \
             patch("terminal_pressure.stress_test") as stress_test:
            result = terminal_pressure.main(
                ["stress", "127.0.0.1", "--port", "8080", "--threads", "2", "--duration", "1"]
            )

        self.assertEqual(result, 0)
        stress_test.assert_called_once_with("127.0.0.1", 8080, 2, 1)

    def test_scan_reports_missing_python_nmap_dependency(self):
        with patch("terminal_pressure.importlib.import_module", side_effect=ImportError("missing")):
            with self.assertRaises(SystemExit) as exc:
                terminal_pressure.scan_vulns("127.0.0.1")

        self.assertIn("python-nmap", str(exc.exception))

    def test_exploit_reports_missing_scapy_dependency(self):
        with patch("terminal_pressure.importlib.import_module", side_effect=ImportError("missing")):
            with self.assertRaises(SystemExit) as exc:
                terminal_pressure.exploit_chain("127.0.0.1")

        self.assertIn("scapy", str(exc.exception))

    def test_positive_int_parser_rejects_zero(self):
        with self.assertRaises(SystemExit):
            terminal_pressure.main(["stress", "127.0.0.1", "--threads", "0"])


if __name__ == "__main__":
    unittest.main()
