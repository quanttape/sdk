import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from quanttape.rules import DEFAULT_RULES


def _compiled_rule(name: str):
    for rule in DEFAULT_RULES:
        if rule.name == name:
            return rule.compile()
    raise AssertionError(f"Rule not found: {name}")


class RulePatternTests(unittest.TestCase):
    def test_market_order_without_limit_matches_plain_entry_market_orders(self):
        pattern = _compiled_rule("Market Order Without Limit")
        self.assertIsNotNone(pattern.search('type="market", tif="day", side="buy"'))
        self.assertIsNotNone(pattern.search("order_type='market', qty=100, symbol='TSLA'"))

    def test_market_order_without_limit_ignores_exit_context(self):
        pattern = _compiled_rule("Market Order Without Limit")
        self.assertIsNone(pattern.search('type="market", tif="day", position_intent="buy_to_close"'))
        self.assertIsNone(pattern.search('order_type="market", action="sell", close_reason="shutdown"'))
        self.assertIsNone(pattern.search('type="market", side="sell", flatten=True'))

    def test_no_error_handling_on_order_matches_plain_submissions(self):
        pattern = _compiled_rule("No Error Handling on Order")
        self.assertIsNotNone(pattern.search("self._api.submit_order(**kwargs)"))
        self.assertIsNotNone(pattern.search("client.place_order(order)"))
        self.assertIsNotNone(pattern.search("broker.create_order(request)"))

    def test_no_error_handling_on_order_ignores_wrapped_returns(self):
        pattern = _compiled_rule("No Error Handling on Order")
        self.assertIsNone(pattern.search("return self._api.submit_order(**kwargs)"))
        self.assertIsNone(pattern.search("yield client.place_order(order)"))

    def test_infinite_loop_risk_matches_plain_while_true(self):
        pattern = _compiled_rule("Infinite Loop Risk")
        self.assertIsNotNone(pattern.search("while True:"))
        self.assertIsNotNone(pattern.search("    while True:  # daemon"))
        self.assertIsNotNone(pattern.search("while 1:"))
        self.assertIsNotNone(pattern.search("    while 1:  # spin"))

    def test_infinite_loop_risk_ignores_noncanonical_loops(self):
        pattern = _compiled_rule("Infinite Loop Risk")
        self.assertIsNone(pattern.search("while not stopped:"))
        self.assertIsNone(pattern.search("if cond: while True:"))
        self.assertIsNone(pattern.search("while True: do_work()"))
        self.assertIsNone(pattern.search("while 1: do_work()"))

    def test_hardcoded_ticker_symbol_matches_real_single_symbol_assignments(self):
        pattern = _compiled_rule("Hardcoded Ticker Symbol")
        self.assertIsNotNone(pattern.search('symbol="AAPL"'))
        self.assertIsNotNone(pattern.search("ticker='NVDA'"))

    def test_hardcoded_ticker_symbol_ignores_aggregate_labels(self):
        pattern = _compiled_rule("Hardcoded Ticker Symbol")
        self.assertIsNone(pattern.search('symbol="ALL"'))
        self.assertIsNone(pattern.search("ticker='AUTO'"))
        self.assertIsNone(pattern.search('symbol="NONE"'))

    def test_sleep_without_kill_switch_matches_hardcoded_sleep_calls(self):
        pattern = _compiled_rule("Sleep Without Kill Switch")
        self.assertIsNotNone(pattern.search("time.sleep(5)"))
        self.assertIsNotNone(pattern.search("time.sleep(0.25)  # poll"))
        self.assertIsNotNone(pattern.search("time.sleep(0.5)"))
        self.assertIsNotNone(pattern.search("time.sleep(1.0)"))

    def test_sleep_without_kill_switch_ignores_variable_or_inline_sleep(self):
        pattern = _compiled_rule("Sleep Without Kill Switch")
        self.assertIsNone(pattern.search("time.sleep(poll_interval)"))
        self.assertIsNone(pattern.search("if paused: time.sleep(1)"))
        self.assertIsNone(pattern.search("await asyncio.sleep(1.5)"))
        self.assertIsNone(pattern.search("await asyncio.sleep(backoff_seconds)"))

    def test_no_position_size_limit_matches_direct_full_account_sizing(self):
        pattern = _compiled_rule("No Position Size Limit")
        self.assertIsNotNone(pattern.search("qty = buying_power / price"))
        self.assertIsNotNone(pattern.search("shares = equity * 0.95 / last_price"))
        self.assertIsNotNone(pattern.search("size = (portfolio_value // price)"))

    def test_no_position_size_limit_ignores_capped_or_risk_budget_sizing(self):
        pattern = _compiled_rule("No Position Size Limit")
        self.assertIsNone(pattern.search("qty = min(max_qty, buying_power / price)"))
        self.assertIsNone(pattern.search("shares = risk_budget / stop_distance"))
        self.assertIsNone(pattern.search("size = notional_cap / price"))
        self.assertIsNone(pattern.search("qty = clip(balance / price, 0, max_qty)"))


    # --- Extended Hours Without Limit Order ---
    def test_extended_hours_matches_true_assignments(self):
        pattern = _compiled_rule("Extended Hours Without Limit Order")
        self.assertIsNotNone(pattern.search("extended_hours=True"))
        self.assertIsNotNone(pattern.search("extended_hours = True"))
        self.assertIsNotNone(pattern.search('extended_hours: True'))

    def test_extended_hours_ignores_false_or_variable(self):
        pattern = _compiled_rule("Extended Hours Without Limit Order")
        self.assertIsNone(pattern.search("extended_hours=False"))
        self.assertIsNone(pattern.search("extended_hours = use_ext"))

    # --- Leverage Without Cap ---
    def test_leverage_without_cap_matches_bare_numeric(self):
        pattern = _compiled_rule("Leverage Without Cap")
        self.assertIsNotNone(pattern.search("leverage = 4"))
        self.assertIsNotNone(pattern.search("margin_multiplier = 10"))
        self.assertIsNotNone(pattern.search("margin_ratio = 2"))

    def test_leverage_without_cap_ignores_capped_or_config(self):
        pattern = _compiled_rule("Leverage Without Cap")
        self.assertIsNone(pattern.search("leverage = min(4, max_leverage)"))
        self.assertIsNone(pattern.search("leverage = config.get('leverage')"))
        self.assertIsNone(pattern.search("margin_multiplier = env.MAX_LEVERAGE"))

    # --- Hardcoded Notional Amount ---
    def test_hardcoded_notional_matches_large_values(self):
        pattern = _compiled_rule("Hardcoded Notional Amount")
        self.assertIsNotNone(pattern.search("notional = 100000"))
        self.assertIsNotNone(pattern.search("order_value = 50000"))
        self.assertIsNotNone(pattern.search("trade_value = 25000"))

    def test_hardcoded_notional_ignores_small_or_variable(self):
        pattern = _compiled_rule("Hardcoded Notional Amount")
        self.assertIsNone(pattern.search("notional = 999"))
        self.assertIsNone(pattern.search("notional = computed_value"))
        self.assertIsNone(pattern.search("order_value = get_notional()"))

    # --- Hardcoded Crypto Pair ---
    def test_hardcoded_crypto_pair_matches_common_pairs(self):
        pattern = _compiled_rule("Hardcoded Crypto Pair")
        self.assertIsNotNone(pattern.search('symbol="BTCUSDT"'))
        self.assertIsNotNone(pattern.search("pair='ETH/USD'"))
        self.assertIsNotNone(pattern.search('ticker="SOLUSDC"'))

    def test_hardcoded_crypto_pair_ignores_variables_and_equity_tickers(self):
        pattern = _compiled_rule("Hardcoded Crypto Pair")
        self.assertIsNone(pattern.search("symbol = get_pair()"))
        self.assertIsNone(pattern.search('symbol="AAPL"'))


if __name__ == "__main__":
    unittest.main()
