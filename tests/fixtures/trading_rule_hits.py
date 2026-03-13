price = 100
buying_power = 100000

while True:
    do_work()
time.sleep(5)
qty = buying_power / price
symbol = "AAPL"
client.submit_order(
    symbol=symbol,
    order_type="market",
    side="buy",
)
