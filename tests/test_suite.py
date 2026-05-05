import asyncio, sys, time, json
import os
# Dynamic — resolves to oracle_v2/ root on any machine
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

PASS = "✅ PASS"
FAIL = "❌ FAIL"
WARN = "⚠️  WARN"

results = []

def test(name: str):
    """Decorator to run and record test"""
    def decorator(fn):
        def wrapper():
            try:
                fn()
                results.append((PASS, name))
                print(f"  {PASS}  {name}")
            except AssertionError as e:
                results.append((FAIL, name, str(e)))
                print(f"  {FAIL}  {name}: {e}")
            except Exception as e:
                results.append((FAIL, name, str(e)))
                print(f"  {FAIL}  {name}: {type(e).__name__}: {e}")
        return wrapper
    return decorator

def async_test(name: str):
    def decorator(fn):
        def wrapper():
            try:
                asyncio.run(fn())
                results.append((PASS, name))
                print(f"  {PASS}  {name}")
            except AssertionError as e:
                results.append((FAIL, name, str(e)))
                print(f"  {FAIL}  {name}: {e}")
            except Exception as e:
                results.append((FAIL, name, str(e)))
                print(f"  {FAIL}  {name}: {type(e).__name__}: {e}")
        return wrapper
    return decorator


# ═══════════════════════════════════════════════════════════════
# SECURITY TESTS
# ═══════════════════════════════════════════════════════════════

print("\n🔐 SECURITY TESTS")
print("─" * 50)

from security.security import KeyVault, RateLimiter, InputSanitizer, AuditLogger

@test("KeyVault: encrypt / decrypt round-trip")
def t_encrypt():
    kv = KeyVault("test_password_123")
    secret = "my_trading_secret_data"
    enc = kv.encrypt(secret)
    assert enc != secret, "Should be encrypted"
    dec = kv.decrypt(enc)
    assert dec == secret, f"Decryption failed: {dec}"

@test("KeyVault: JWT sign and verify")
def t_jwt():
    kv = KeyVault("test_password_123")
    token = kv.sign_jwt({"user": "trader1", "role": "user"}, expires_minutes=5)
    assert isinstance(token, str) and len(token) > 20
    payload = kv.verify_jwt(token)
    assert payload is not None
    assert payload["user"] == "trader1"

@test("KeyVault: JWT tampered token rejected")
def t_jwt_tamper():
    kv = KeyVault("test_password_123")
    token = kv.sign_jwt({"user": "hacker"})
    bad_token = token[:-5] + "XXXXX"
    result = kv.verify_jwt(bad_token)
    assert result is None, "Tampered token should be rejected"

@test("KeyVault: API key generate and verify")
def t_apikey():
    kv = KeyVault("test_password_123")
    key = kv.generate_api_key("user_001")
    assert kv.verify_api_key("user_001", key) is True
    assert kv.verify_api_key("user_001", "wrong_key") is False

@test("RateLimiter: allows requests within limit")
def t_ratelimit_allow():
    rl = RateLimiter()
    for _ in range(10):
        result = rl.check("test_user", max_requests=20, window_seconds=60)
        assert result is True, "Should allow within limit"

@test("RateLimiter: blocks after exhaustion")
def t_ratelimit_block():
    rl = RateLimiter()
    for _ in range(5):
        rl.check("heavy_user", max_requests=5, window_seconds=60)
    blocked = rl.check("heavy_user", max_requests=5, window_seconds=60)
    assert blocked is False, "Should be blocked after exhaustion"

@test("InputSanitizer: SQL injection blocked")
def t_sql_inject():
    try:
        InputSanitizer.sanitize("SELECT * FROM users; DROP TABLE users;--")
        assert False, "Should have raised ValueError"
    except ValueError as e:
        assert "SQL" in str(e) or "injection" in str(e).lower()

@test("InputSanitizer: XSS blocked")
def t_xss():
    try:
        InputSanitizer.sanitize("<script>alert('xss')</script>")
        assert False, "Should have raised ValueError"
    except ValueError:
        pass

@test("InputSanitizer: command injection blocked")
def t_cmd_inject():
    try:
        InputSanitizer.sanitize("normal text; rm -rf /")
        assert False, "Should have raised ValueError"
    except ValueError:
        pass

@test("InputSanitizer: valid input passes")
def t_valid_input():
    result = InputSanitizer.sanitize("NIFTY stock prediction today")
    assert result == "NIFTY stock prediction today"

@test("InputSanitizer: ticker sanitization valid")
def t_ticker_valid():
    assert InputSanitizer.sanitize_ticker("RELIANCE") == "RELIANCE"
    assert InputSanitizer.sanitize_ticker("tcs") == "TCS"
    assert InputSanitizer.sanitize_ticker("  nifty  ") == "NIFTY"

@test("InputSanitizer: ticker sanitization blocks invalid")
def t_ticker_invalid():
    try:
        InputSanitizer.sanitize_ticker("RELIANCE; DROP TABLE")
        assert False, "Should reject bad ticker"
    except ValueError:
        pass

@test("AuditLogger: writes and reads logs")
def t_audit():
    import tempfile, os
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    try:
        logger = AuditLogger(db_path)
        logger.log("TEST", "unit_test", "SUCCESS", user_id="tester", details="test log")
        rows = logger.get_recent(5)
        assert len(rows) >= 1
        assert "unit_test" in str(rows[0])
    finally:
        os.unlink(db_path)

# Run security tests
t_encrypt(); t_jwt(); t_jwt_tamper(); t_apikey()
t_ratelimit_allow(); t_ratelimit_block()
t_sql_inject(); t_xss(); t_cmd_inject(); t_valid_input()
t_ticker_valid(); t_ticker_invalid(); t_audit()


# ═══════════════════════════════════════════════════════════════
# DSA ALGORITHM TESTS
# ═══════════════════════════════════════════════════════════════

print("\n⚡ DSA ALGORITHM TESTS")
print("─" * 50)

from core.internet_engine import BloomFilter, FinancialTrie, KMPSearch, TickBuffer, SignalHeap

@test("BloomFilter: contains added items")
def t_bloom_contains():
    bf = BloomFilter(capacity=1000)
    bf.add("https://example.com/news/1")
    bf.add("https://example.com/news/2")
    assert "https://example.com/news/1" in bf
    assert "https://example.com/news/2" in bf

@test("BloomFilter: does not contain un-added items (high probability)")
def t_bloom_not_contains():
    bf = BloomFilter(capacity=10000)
    fp_count = sum(1 for i in range(1000)
                   if f"https://never-added-{i}.com" in bf)
    assert fp_count < 10, f"Too many false positives: {fp_count}"

@test("FinancialTrie: finds keywords in text")
def t_trie_search():
    trie = FinancialTrie()
    findings = trie.search_in_text("Reliance shows bullish breakout with high volume surge")
    keywords = [f["keyword"] for f in findings]
    assert any(k in ["bullish", "breakout", "volume surge"] for k in keywords)

@test("FinancialTrie: returns sentiment scores")
def t_trie_scores():
    trie = FinancialTrie()
    findings = trie.search_in_text("strong bullish breakout signal")
    assert all("score" in f for f in findings)
    scores = [f["score"] for f in findings]
    assert any(s > 0 for s in scores)

@test("KMP: finds pattern correctly")
def t_kmp_basic():
    positions = KMPSearch.search("NIFTY breaks NIFTY all-time high", "NIFTY")
    assert len(positions) == 2
    assert positions[0] == 0
    assert positions[1] == 13

@test("KMP: no match returns empty list")
def t_kmp_no_match():
    assert KMPSearch.search("hello world", "xyz") == []

@test("KMP: empty pattern / text handled")
def t_kmp_empty():
    assert KMPSearch.search("", "abc") == []
    assert KMPSearch.search("abc", "") == []

@test("TickBuffer: push and retrieve")
def t_tickbuffer_push():
    tb = TickBuffer(window_size=5)
    for i in range(5):
        tb.push({"close": 100.0 + i, "volume": 1000})
    assert tb.latest_close() == 104.0
    assert len(tb.get_window()) == 5

@test("TickBuffer: SMA calculation")
def t_tickbuffer_sma():
    tb = TickBuffer(window_size=4)
    for price in [100, 102, 104, 106]:
        tb.push({"close": float(price)})
    sma = tb.sma()
    assert sma is not None
    assert abs(sma - 103.0) < 0.01

@test("TickBuffer: RSI calculation")
def t_tickbuffer_rsi():
    tb = TickBuffer(window_size=30)
    prices = [100 + i*0.5 for i in range(25)]  # Trending up
    for p in prices:
        tb.push({"close": p})
    rsi = tb.rsi(period=14)
    assert rsi is not None
    assert 50 < rsi <= 100, f"RSI should be > 50 for uptrend, got {rsi}"

@test("SignalHeap: max-heap ordering")
def t_heap_order():
    heap = SignalHeap()
    heap.push(0.3, {"signal": "weak"})
    heap.push(0.9, {"signal": "strong"})
    heap.push(0.6, {"signal": "medium"})
    top = heap.peek_top(3)
    assert top[0]["signal"] == "strong"

@test("SignalHeap: pop returns highest priority")
def t_heap_pop():
    heap = SignalHeap()
    heap.push(0.4, {"id": "a"})
    heap.push(0.8, {"id": "b"})
    item = heap.pop()
    assert item["id"] == "b"

# Run DSA tests
t_bloom_contains(); t_bloom_not_contains()
t_trie_search(); t_trie_scores()
t_kmp_basic(); t_kmp_no_match(); t_kmp_empty()
t_tickbuffer_push(); t_tickbuffer_sma(); t_tickbuffer_rsi()
t_heap_order(); t_heap_pop()


# ═══════════════════════════════════════════════════════════════
# PREDICTION ENGINE TESTS
# ═══════════════════════════════════════════════════════════════

print("\n📈 PREDICTION ENGINE TESTS")
print("─" * 50)

from models.prediction_engine import python_price_model, lstm_pattern_signal, SignalFusion

@test("Python price model: returns valid signal")
def t_price_model_basic():
    prices = [100.0, 101.0, 102.5, 103.0, 102.0, 104.5, 105.0]
    signal = python_price_model(prices)
    assert signal.direction in ["BUY", "SELL", "HOLD"]
    assert 0.0 <= signal.confidence <= 1.0
    assert -1.0 <= signal.score <= 1.0
    assert signal.volatility >= 0

@test("Python price model: uptrend → BUY signal")
def t_price_model_uptrend():
    prices = [100 + i*1.5 for i in range(20)]
    signal = python_price_model(prices)
    assert signal.direction in ["BUY", "HOLD"], f"Expected BUY/HOLD, got {signal.direction}"

@test("Python price model: downtrend → SELL signal")
def t_price_model_downtrend():
    prices = [200 - i*2.0 for i in range(20)]
    signal = python_price_model(prices)
    assert signal.direction in ["SELL", "HOLD"], f"Expected SELL/HOLD, got {signal.direction}"

@test("Python price model: insufficient data handled")
def t_price_model_short():
    prices = [100.0, 101.0]
    signal = python_price_model(prices)
    assert signal.direction == "HOLD"
    assert signal.confidence == 0.5

@test("LSTM pattern signal: returns float in [-1,1]")
def t_lstm_basic():
    prices = [100 + i*0.3 for i in range(30)]
    score = lstm_pattern_signal(prices)
    assert -1.0 <= score <= 1.0

@test("LSTM: breakout up → positive score")
def t_lstm_breakout_up():
    base = [100.0] * 20
    surge = [105.0, 106.0, 107.0, 108.0, 109.0]
    prices = base + surge
    score = lstm_pattern_signal(prices)
    assert score > 0, f"Breakout up should give positive score, got {score}"

@test("LSTM: breakdown → negative score")
def t_lstm_breakdown():
    base = [100.0] * 20
    drop = [95.0, 94.0, 93.5, 93.0, 92.5]
    prices = base + drop
    score = lstm_pattern_signal(prices)
    assert score < 0, f"Breakdown should give negative score, got {score}"

@test("SignalFusion: produces valid FinalSignal")
def t_fusion_basic():
    fusion = SignalFusion()
    prices = [100 + i*0.5 for i in range(30)]
    sig = fusion.compute(prices, sentiment_score=0.4, ticker="TEST")
    assert sig.action in ["STRONG BUY","BUY","HOLD","SELL","STRONG SELL"]
    assert 0.0 <= sig.confidence <= 1.0
    assert sig.stop_loss < sig.entry_price
    assert sig.take_profit > sig.entry_price
    assert sig.risk_level in ["LOW","MEDIUM","HIGH"]

@test("SignalFusion: risk management prices correct")
def t_fusion_risk():
    fusion = SignalFusion()
    prices = [2850.0] * 30
    sig = fusion.compute(prices, sentiment_score=0.0, ticker="RELIANCE")
    assert abs(sig.stop_loss  - sig.entry_price * 0.985) < 1.0
    assert abs(sig.take_profit - sig.entry_price * 1.030) < 1.0

@test("SignalFusion: confidence ≤ 1.0")
def t_fusion_confidence_bounded():
    fusion = SignalFusion()
    prices = [100 + i for i in range(50)]
    sig = fusion.compute(prices, sentiment_score=1.0, ticker="EXTREME")
    assert sig.confidence <= 1.0, f"Confidence overflow: {sig.confidence}"

@test("SignalFusion: to_dict serializable")
def t_fusion_dict():
    fusion = SignalFusion()
    prices = [100.0] * 20
    sig = fusion.compute(prices)
    d = fusion.to_dict(sig)
    assert isinstance(d, dict)
    # Must be JSON serializable
    dumped = json.dumps(d)
    assert len(dumped) > 10

# Run prediction tests
t_price_model_basic(); t_price_model_uptrend()
t_price_model_downtrend(); t_price_model_short()
t_lstm_basic(); t_lstm_breakout_up(); t_lstm_breakdown()
t_fusion_basic(); t_fusion_risk(); t_fusion_confidence_bounded(); t_fusion_dict()


# ═══════════════════════════════════════════════════════════════
# INTEGRATION / AGENT TESTS
# ═══════════════════════════════════════════════════════════════

print("\n🤖 INTEGRATION TESTS (AGENT)")
print("─" * 50)

from core.agent import OracleAgent

@async_test("Agent: initializes without error")
async def t_agent_init():
    agent = OracleAgent("test_master_key")
    status = await agent.initialize()
    assert "version" in status
    assert status["security"] == "ready"
    await agent.close()

@async_test("Agent: predict returns success response")
async def t_agent_predict():
    agent = OracleAgent("test_master_key")
    await agent.initialize()
    result = await agent.predict("RELIANCE", user_id="test_user")
    assert result["status"] == "success"
    assert "signal" in result
    assert "sentiment" in result
    assert "analysis" in result
    await agent.close()

@async_test("Agent: invalid ticker rejected")
async def t_agent_bad_ticker():
    agent = OracleAgent("test_master_key")
    result = await agent.predict("'; DROP TABLE--", user_id="attacker")
    assert result.get("status") == "rejected"
    await agent.close()

@async_test("Agent: rate limiting works")
async def t_agent_ratelimit():
    agent = OracleAgent("test_master_key")
    await agent.initialize()
    # Exhaust rate limit
    for _ in range(30):
        agent.limiter.check("flood_user", max_requests=30, window_seconds=60)
    result = await agent.predict("NIFTY", user_id="flood_user")
    assert result.get("status") == "blocked"
    await agent.close()

@async_test("Agent: multiple tickers work")
async def t_agent_multi_ticker():
    agent = OracleAgent("test_master_key")
    await agent.initialize()
    for ticker in ["NIFTY", "TCS", "HDFC"]:
        result = await agent.predict(ticker, user_id="multi_test")
        assert result["status"] == "success", f"Failed for {ticker}"
        assert result["signal"]["action"] in [
            "STRONG BUY","BUY","HOLD","SELL","STRONG SELL"
        ]
    await agent.close()

@async_test("Agent: custom prices accepted")
async def t_agent_custom_prices():
    agent = OracleAgent("test_master_key")
    await agent.initialize()
    prices = [100 + i*0.8 for i in range(40)]
    result = await agent.predict("INFY", prices=prices, user_id="price_test")
    assert result["status"] == "success"
    assert result["meta"]["prices_used"] == 40
    await agent.close()

@async_test("Agent: audit log records predictions")
async def t_agent_audit():
    agent = OracleAgent("test_master_key")
    await agent.initialize()
    await agent.predict("SBI", user_id="audit_test")
    logs = agent.audit.get_recent(5)
    actions = [row[5] for row in logs]
    assert any("predict" in str(a) for a in actions)
    await agent.close()

# Run integration tests
t_agent_init(); t_agent_predict(); t_agent_bad_ticker()
t_agent_ratelimit(); t_agent_multi_ticker()
t_agent_custom_prices(); t_agent_audit()


# ═══════════════════════════════════════════════════════════════
# FINAL REPORT
# ═══════════════════════════════════════════════════════════════

print("\n" + "═"*50)
print("  ORACLE v2 — TEST REPORT")
print("═"*50)

passed = sum(1 for r in results if r[0] == PASS)
failed = sum(1 for r in results if r[0] == FAIL)
total  = len(results)

print(f"\n  Total tests : {total}")
print(f"  Passed      : {passed} ✅")
print(f"  Failed      : {failed} {'❌' if failed else '✅'}")
print(f"  Score       : {passed/total*100:.1f}%")

if failed > 0:
    print("\n  Failed tests:")
    for r in results:
        if r[0] == FAIL:
            print(f"    ❌ {r[1]}: {r[2] if len(r)>2 else ''}")

print("\n" + "═"*50)
status_line = "🟢 ALL SYSTEMS GO — ORACLE v2 READY FOR DEPLOYMENT" if failed == 0 \
              else f"🟡 {failed} TEST(S) FAILED — review before deployment"
print(f"  {status_line}")
print("═"*50 + "\n")

sys.exit(0 if failed == 0 else 1)
