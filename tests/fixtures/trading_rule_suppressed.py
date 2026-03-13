def close_position(api, done):
    while True:
        if done:
            break
        do_work()
    return api.submit_order(
        symbol="ALL",
        order_type="market",
        position_intent="sell_to_close",
    )
