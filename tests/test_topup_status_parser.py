import unittest

from server import AdminHandler


class TopupStatusParserTests(unittest.TestCase):
    def setUp(self) -> None:
        self.handler = object.__new__(AdminHandler)

    def derive(self, payload: dict) -> tuple[str, str]:
        return AdminHandler._derive_topup_status(self.handler, payload)

    def test_valid_transaction_status_is_success(self) -> None:
        payload = {
            "success": True,
            "message": "Transaction Successful",
            "response": {
                "status": 200,
                "message": "Successful",
                "data": {"transaction_status": "VALID"},
            },
        }
        status, _ = self.derive(payload)
        self.assertEqual(status, "success")

    def test_pending_status_wins_over_wrapper_success(self) -> None:
        payload = {
            "success": True,
            "message": "Transaction Successful",
            "response": {
                "status": 200,
                "message": "Successful",
                "data": {"transaction_status": "PENDING"},
            },
        }
        status, message = self.derive(payload)
        self.assertEqual(status, "pending")
        self.assertEqual(message, "Transaction Pending")

    def test_invalid_status_is_failed(self) -> None:
        payload = {
            "success": True,
            "response": {"data": {"transaction_status": "INVALID"}},
        }
        status, _ = self.derive(payload)
        self.assertEqual(status, "failed")

    def test_pending_has_precedence_over_success_markers(self) -> None:
        payload = {
            "success": True,
            "response": {
                "status": 200,
                "data": {
                    "transaction_status": "VALID",
                    "payment_status": "PENDING",
                },
            },
        }
        status, _ = self.derive(payload)
        self.assertEqual(status, "pending")

    def test_ambiguous_envelope_only_defaults_to_pending(self) -> None:
        payload = {
            "success": True,
            "message": "Request accepted",
        }
        status, _ = self.derive(payload)
        self.assertEqual(status, "pending")


if __name__ == "__main__":
    unittest.main()
