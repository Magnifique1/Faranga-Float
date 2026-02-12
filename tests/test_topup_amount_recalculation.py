import unittest
from decimal import Decimal

from server import _canonical_topup_amounts_from_user_percentage


class TopupAmountRecalculationTests(unittest.TestCase):
    def test_uses_fallback_net_amount_when_present(self) -> None:
        amount, fee, total = _canonical_topup_amounts_from_user_percentage(
            user_fee_percentage=Decimal("10.00"),
            fallback_amount=Decimal("100.00"),
            amount=Decimal("110.00"),
            platform_fee=Decimal("10.00"),
            total_charge=Decimal("110.00"),
        )
        self.assertEqual(amount, Decimal("100.00"))
        self.assertEqual(fee, Decimal("10.00"))
        self.assertEqual(total, Decimal("110.00"))

    def test_derives_net_from_total_when_gateway_amount_is_gross(self) -> None:
        amount, fee, total = _canonical_topup_amounts_from_user_percentage(
            user_fee_percentage=Decimal("10.00"),
            fallback_amount=None,
            amount=Decimal("220.00"),
            platform_fee=Decimal("20.00"),
            total_charge=Decimal("220.00"),
        )
        self.assertEqual(amount, Decimal("200.00"))
        self.assertEqual(fee, Decimal("20.00"))
        self.assertEqual(total, Decimal("220.00"))

    def test_treats_amount_as_net_when_no_total_signal(self) -> None:
        amount, fee, total = _canonical_topup_amounts_from_user_percentage(
            user_fee_percentage=Decimal("10.00"),
            fallback_amount=None,
            amount=Decimal("20.00"),
            platform_fee=Decimal("0.00"),
            total_charge=Decimal("20.00"),
        )
        self.assertEqual(amount, Decimal("20.00"))
        self.assertEqual(fee, Decimal("2.00"))
        self.assertEqual(total, Decimal("22.00"))


if __name__ == "__main__":
    unittest.main()
