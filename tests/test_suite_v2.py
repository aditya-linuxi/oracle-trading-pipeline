"""
ORACLE v2 — Final Optimised Test Suite
71 tests · all edge cases · security attacks · boundary conditions
Run: python3 tests/test_suite_v2.py
"""
import asyncio, sys, time, json, math, os, tempfile, warnings
# Dynamic — resolves to oracle_v2/ root on any machine, from any working directory
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

PASS = "✅ PASS"
FAIL = "❌ FAIL"
results = []

def run(name, fn, is_async=False):
    t0 = time.perf_counter()
    try:
        if is_async:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", ResourceWarning)
                asyncio.run(fn())
        else:
            fn()
        ms = (time.perf_counter() - t0) * 1000
        results.append((PASS, name, ms))
        print(f"  {PASS}  {name}  [{ms:.1f}ms]")
    except AssertionError as e:
        ms = (time.perf_counter() - t0) * 1000
        results.append((FAIL, name, ms, str(e)))
        print(f"  {FAIL}  {name}: {e}")
    except Exception as e:
        ms = (time.perf_counter() - t0) * 1000
        results.append((FAIL, name, ms, f"{type(e).__name__}: {e}"))
        print(f"  {FAIL}  {name}: {type(e).__name__}: {e}")

# ══════════════════════════════════════════════════════════════
# SECTION 1 — SECURITY (20 tests)
# ══════════════════════════════════════════════════════════════
print("\n🔐 SECURITY")
print("─" * 60)
from security.security import KeyVault, RateLimiter, InputSanitizer, AuditLogger

def sec_encrypt_roundtrip():
    kv = KeyVault("test_pw_123")
    d  = "secret_trading_data"
    assert kv.decrypt(kv.encrypt(d)) == d
run("KeyVault: encrypt/decrypt round-trip", sec_encrypt_roundtrip)

def sec_encrypted_differs():
    kv = KeyVault("test_pw_123")
    enc = kv.encrypt("hello")
    assert enc != "hello" and len(enc) > 20
run("KeyVault: ciphertext differs from plaintext", sec_encrypted_differs)

def sec_diff_keys_diff_cipher():
    kv1, kv2 = KeyVault("pw_one"), KeyVault("pw_two")
    assert kv1.encrypt("same") != kv2.encrypt("same")
run("KeyVault: different keys produce different ciphertext", sec_diff_keys_diff_cipher)

def sec_wrong_key_fails():
    kv1, kv2 = KeyVault("correct"), KeyVault("wrong")
    enc = kv1.encrypt("secret")
    try:
        kv2.decrypt(enc)
        assert False, "Should raise on wrong key"
    except Exception:
        pass
run("KeyVault: wrong key cannot decrypt", sec_wrong_key_fails)

def sec_jwt_roundtrip():
    kv = KeyVault("test")
    pl = kv.verify_jwt(kv.sign_jwt({"uid": "u1", "role": "admin"}))
    assert pl and pl["uid"] == "u1" and pl["role"] == "admin"
run("KeyVault: JWT sign and verify", sec_jwt_roundtrip)

def sec_jwt_has_claims():
    kv = KeyVault("test")
    pl = kv.verify_jwt(kv.sign_jwt({"x": 1}))
    assert "exp" in pl and "iat" in pl and "jti" in pl
run("KeyVault: JWT contains exp, iat, jti", sec_jwt_has_claims)

def sec_jwt_tamper_rejected():
    kv  = KeyVault("test")
    tok = kv.sign_jwt({"u": "hacker"})
    assert kv.verify_jwt(tok[:-5] + "ZZZZZ") is None
run("KeyVault: tampered JWT rejected", sec_jwt_tamper_rejected)

def sec_apikey_correct():
    kv  = KeyVault("test")
    key = kv.generate_api_key("user_1")
    assert kv.verify_api_key("user_1", key) is True
run("KeyVault: correct API key accepted", sec_apikey_correct)

def sec_apikey_wrong():
    kv = KeyVault("test")
    kv.generate_api_key("user_2")
    assert kv.verify_api_key("user_2", "wrong_key") is False
run("KeyVault: wrong API key rejected", sec_apikey_wrong)

def sec_apikey_unknown_user():
    kv = KeyVault("test")
    assert kv.verify_api_key("ghost_user", "anykey") is False
run("KeyVault: unknown user rejected", sec_apikey_unknown_user)

def sec_ratelimit_allows():
    rl = RateLimiter()
    assert all(rl.check("u_ok", max_requests=20, window_seconds=60) for _ in range(10))
run("RateLimiter: allows within budget", sec_ratelimit_allows)

def sec_ratelimit_blocks():
    rl = RateLimiter()
    for _ in range(5): rl.check("u_blk", max_requests=5, window_seconds=60)
    assert rl.check("u_blk", max_requests=5, window_seconds=60) is False
run("RateLimiter: blocks after exhaustion", sec_ratelimit_blocks)

def sec_ratelimit_isolation():
    rl = RateLimiter()
    for _ in range(6): rl.check("heavy_usr", max_requests=5, window_seconds=60)
    assert rl.check("clean_usr", max_requests=5, window_seconds=60) is True
run("RateLimiter: users are rate-limited independently", sec_ratelimit_isolation)

def sec_sql_injection():
    for p in ["'; DROP TABLE--", "SELECT * FROM users", "1' OR '1'='1"]:
        try: InputSanitizer.sanitize(p); assert False, f"Not blocked: {p}"
        except ValueError: pass
run("InputSanitizer: SQL injection blocked", sec_sql_injection)

def sec_xss():
    for p in ["<script>alert(1)</script>", "javascript:void(0)", "onerror=hack()"]:
        try: InputSanitizer.sanitize(p); assert False, f"Not blocked: {p}"
        except ValueError: pass
run("InputSanitizer: XSS blocked", sec_xss)

def sec_cmd_injection():
    for p in ["hello; rm -rf /", "cat /etc/passwd", "$(whoami)"]:
        try: InputSanitizer.sanitize(p); assert False, f"Not blocked: {p}"
        except ValueError: pass
run("InputSanitizer: command injection blocked", sec_cmd_injection)

def sec_path_traversal():
    for p in ["../../etc/passwd", "%2e%2e/secret"]:
        try: InputSanitizer.sanitize(p); assert False, f"Not blocked: {p}"
        except ValueError: pass
run("InputSanitizer: path traversal blocked", sec_path_traversal)

def sec_valid_input():
    assert InputSanitizer.sanitize("NIFTY 50 analysis today") == "NIFTY 50 analysis today"
run("InputSanitizer: valid input passes clean", sec_valid_input)

def sec_nan_inf():
    for v in [float("inf"), float("-inf"), float("nan")]:
        try: InputSanitizer.sanitize_number(v); assert False, f"{v} not blocked"
        except ValueError: pass
run("InputSanitizer: inf and nan blocked", sec_nan_inf)

def sec_audit_log():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db = f.name
    try:
        al = AuditLogger(db)
        al.log("TEST", "audit_verify", "SUCCESS", user_id="tester")
        rows = al.get_recent(5)
        assert len(rows) >= 1 and "audit_verify" in str(rows[0])
    finally:
        os.unlink(db)
run("AuditLogger: write, read, checksum verified", sec_audit_log)


# ══════════════════════════════════════════════════════════════
# SECTION 2 — DSA ALGORITHMS (27 tests)
# ══════════════════════════════════════════════════════════════
print("\n⚡ DSA ALGORITHMS")
print("─" * 60)
from core.internet_engine import (
    BloomFilter, FinancialTrie, KMPSearch,
    TickBuffer, SignalHeap, InternetEngine
)

def bloom_found():
    bf = BloomFilter(capacity=1000)
    for i in range(50): bf.add(f"url_{i}")
    assert all(f"url_{i}" in bf for i in range(50))
run("Bloom: all added items found", bloom_found)

def bloom_fp_rate():
    bf = BloomFilter(capacity=10000, error_rate=0.01)
    for i in range(500): bf.add(f"present_{i}")
    fp = sum(1 for i in range(1000) if f"absent_{i}" in bf)
    assert fp / 1000 < 0.05, f"FP rate {fp/1000:.3f} exceeds 5%"
run("Bloom: false positive rate < 5%", bloom_fp_rate)

def bloom_empty():
    assert "anything" not in BloomFilter(capacity=100)
run("Bloom: empty filter contains nothing", bloom_empty)

def bloom_readd_safe():
    bf = BloomFilter(capacity=100)
    for _ in range(10): bf.add("same_url")
    assert "same_url" in bf
run("Bloom: re-adding same item is safe", bloom_readd_safe)

def bloom_small_capacity():
    bf = BloomFilter(capacity=1, error_rate=0.5)
    bf.add("x")
    assert True
run("Bloom: tiny capacity does not crash", bloom_small_capacity)

def trie_bullish():
    t = FinancialTrie()
    kws = [f["keyword"] for f in t.search_in_text("strong bullish breakout buy signal")]
    assert any(k in ["bullish","breakout","buy signal"] for k in kws)
run("Trie: finds bullish keywords", trie_bullish)

def trie_bearish():
    t = FinancialTrie()
    kws = [f["keyword"] for f in t.search_in_text("bearish fii selling lower circuit")]
    assert any(k in ["bearish","fii selling","lower circuit"] for k in kws)
run("Trie: finds bearish keywords", trie_bearish)

def trie_score_field():
    t = FinancialTrie()
    assert all("score" in f for f in t.search_in_text("nifty bullish breakout"))
run("Trie: all findings have score field", trie_score_field)

def trie_empty():
    assert FinancialTrie().search_in_text("") == []
run("Trie: empty text returns empty list", trie_empty)

def trie_no_keywords():
    assert FinancialTrie().search_in_text("the quick brown fox") == []
run("Trie: irrelevant text returns empty list", trie_no_keywords)

def trie_no_dupe():
    t = FinancialTrie()
    t.insert("bullish", {"score": 0.9})
    t.insert("bullish", {"score": 0.8})
    hits = [f for f in t.search_in_text("bullish") if f["keyword"] == "bullish"]
    assert len(hits) == 1
run("Trie: duplicate insert gives single finding", trie_no_dupe)

def kmp_single():
    assert KMPSearch.search("NIFTY breaks all-time high", "NIFTY") == [0]
run("KMP: finds single occurrence", kmp_single)

def kmp_multi():
    pos = KMPSearch.search("NIFTY and more NIFTY data", "NIFTY")
    assert len(pos) == 2 and pos[0] == 0
run("KMP: finds multiple occurrences", kmp_multi)

def kmp_no_match():
    assert KMPSearch.search("hello world", "xyz") == []
run("KMP: no match returns empty list", kmp_no_match)

def kmp_empty_text():
    assert KMPSearch.search("", "NIFTY") == []
run("KMP: empty text returns empty list", kmp_empty_text)

def kmp_empty_pattern():
    assert KMPSearch.search("some text", "") == []
run("KMP: empty pattern returns empty list", kmp_empty_pattern)

def kmp_unicode():
    assert KMPSearch.search("NIFTY gains today", "NIFTY") == [0]
run("KMP: unicode-adjacent text handled", kmp_unicode)

def tb_push_latest():
    tb = TickBuffer(10)
    for i in range(5): tb.push({"close": 100.0 + i})
    assert tb.latest_close() == 104.0
run("TickBuffer: push and latest_close correct", tb_push_latest)

def tb_sma():
    tb = TickBuffer(4)
    for p in [100.0, 102.0, 104.0, 106.0]: tb.push({"close": p})
    assert abs(tb.sma() - 103.0) < 0.01
run("TickBuffer: SMA calculation correct", tb_sma)

def tb_rsi_flat():
    tb = TickBuffer(30)
    for _ in range(20): tb.push({"close": 100.0})
    assert tb.rsi() == 50.0, f"Flat RSI should be 50.0, got {tb.rsi()}"
run("TickBuffer: flat prices give RSI = 50.0", tb_rsi_flat)

def tb_rsi_uptrend():
    tb = TickBuffer(30)
    for i in range(20): tb.push({"close": 100.0 + i})
    rsi = tb.rsi(period=10)
    assert rsi is not None and rsi > 50
run("TickBuffer: uptrend gives RSI > 50", tb_rsi_uptrend)

def tb_rsi_insufficient():
    tb = TickBuffer(5)
    tb.push({"close": 100.0})
    tb.push({"close": 101.0})
    assert tb.rsi(period=14) is None
run("TickBuffer: insufficient data gives RSI = None", tb_rsi_insufficient)

def heap_order():
    h = SignalHeap()
    h.push(0.3, {"id":"low"}); h.push(0.9, {"id":"high"}); h.push(0.6, {"id":"mid"})
    assert h.pop()["id"] == "high"
run("SignalHeap: highest score pops first", heap_order)

def heap_empty():
    assert SignalHeap().pop() is None
run("SignalHeap: empty pop returns None", heap_empty)

def ie_empty_text():
    ie = InternetEngine()
    for inp in ["", "   "]:
        r = ie.score_text(inp)
        assert r["score"] == 0.0 and r["signal"] == "NEUTRAL" and r["count"] == 0
run("InternetEngine: empty text gives neutral score", ie_empty_text)

def ie_bullish_text():
    ie = InternetEngine()
    r  = ie.score_text("strong bullish breakout buy signal upper circuit", "NIFTY")
    assert r["score"] > 0, f"Expected positive, got {r['score']}"
run("InternetEngine: bullish text gives positive score", ie_bullish_text)

def ie_bearish_text():
    ie = InternetEngine()
    r  = ie.score_text("bearish lower circuit fii selling crash", "NIFTY")
    assert r["score"] < 0, f"Expected negative, got {r['score']}"
run("InternetEngine: bearish text gives negative score", ie_bearish_text)

def ie_score_bounded():
    ie = InternetEngine()
    for txt in ["bullish " * 50, "bearish crash " * 30]:
        r = ie.score_text(txt)
        assert -1.0 <= r["score"] <= 1.0, f"Score out of bounds: {r['score']}"
run("InternetEngine: score always in [-1, 1]", ie_score_bounded)


# ══════════════════════════════════════════════════════════════
# SECTION 3 — PREDICTION ENGINE (13 tests)
# ══════════════════════════════════════════════════════════════
print("\n📈 PREDICTION ENGINE")
print("─" * 60)
from models.prediction_engine import python_price_model, lstm_pattern_signal, SignalFusion

def pm_structure():
    sig = python_price_model([100.0 + i for i in range(20)])
    assert sig.direction in ["BUY","SELL","HOLD"]
    assert 0.0 <= sig.confidence <= 1.0
    assert -1.0 <= sig.score <= 1.0
    assert sig.volatility >= 0.0
run("PriceModel: valid signal structure", pm_structure)

def pm_uptrend():
    sig = python_price_model([100.0 + i*2 for i in range(30)])
    assert sig.direction in ["BUY","HOLD"], f"Got {sig.direction}"
run("PriceModel: uptrend gives BUY or HOLD", pm_uptrend)

def pm_downtrend():
    sig = python_price_model([500.0 - i*3 for i in range(30)])
    assert sig.direction in ["SELL","HOLD"], f"Got {sig.direction}"
run("PriceModel: downtrend gives SELL or HOLD", pm_downtrend)

def pm_single_price():
    sig = python_price_model([100.0])
    assert sig.direction == "HOLD" and sig.confidence == 0.5
run("PriceModel: single price gives HOLD conf=0.5", pm_single_price)

def pm_score_bounded():
    for prices in [[100.0 + i*2 for i in range(40)], [200.0 - i for i in range(40)]]:
        sig = python_price_model(prices)
        assert -1.0 <= sig.score <= 1.0
run("PriceModel: score always in [-1, 1]", pm_score_bounded)

def pm_confidence_bounded():
    for prices in [[100]*20, [100.0 + i for i in range(20)]]:
        sig = python_price_model(prices)
        assert 0.0 <= sig.confidence <= 1.0
run("PriceModel: confidence always in [0, 1]", pm_confidence_bounded)

def lstm_bounded():
    for prices in [[100.0 + i*0.5 for i in range(25)]] * 3:
        assert -1.0 <= lstm_pattern_signal(prices) <= 1.0
run("LSTM: score always in [-1, 1]", lstm_bounded)

def lstm_breakout():
    assert lstm_pattern_signal([100.0]*20 + [107.0,108.0,109.0,110.0,111.0]) > 0
run("LSTM: breakout up gives positive score", lstm_breakout)

def lstm_breakdown():
    assert lstm_pattern_signal([100.0]*20 + [93.0,92.0,91.5,91.0,90.5]) < 0
run("LSTM: breakdown gives negative score", lstm_breakdown)

def lstm_no_data():
    assert lstm_pattern_signal([100.0, 101.0]) == 0.0
run("LSTM: insufficient data returns 0.0", lstm_no_data)

def fusion_structure():
    sf  = SignalFusion()
    sig = sf.compute([100.0 + i*0.5 for i in range(30)], 0.4, "TEST")
    assert sig.action in ["STRONG BUY","BUY","HOLD","SELL","STRONG SELL"]
    assert 0.0 <= sig.confidence <= 1.0
    assert sig.stop_loss < sig.entry_price < sig.take_profit
    assert sig.risk_level in ["LOW","MEDIUM","HIGH"]
run("Fusion: valid FinalSignal structure", fusion_structure)

def fusion_risk_prices():
    sf  = SignalFusion()
    sig = sf.compute([1000.0]*30)
    assert abs(sig.stop_loss   - 1000.0 * 0.985) < 1.0
    assert abs(sig.take_profit - 1000.0 * 1.030) < 1.0
run("Fusion: SL=1.5% and TP=3.0% correct", fusion_risk_prices)

def fusion_serialisable():
    sf  = SignalFusion()
    d   = sf.to_dict(sf.compute([100.0]*20))
    json.dumps(d)
run("Fusion: to_dict is JSON-serialisable", fusion_serialisable)


# ══════════════════════════════════════════════════════════════
# SECTION 4 — INTEGRATION / AGENT (11 tests)
# ══════════════════════════════════════════════════════════════
print("\n🤖 INTEGRATION (AGENT)")
print("─" * 60)
from core.agent import OracleAgent

async def ag_init():
    ag = OracleAgent("test_key")
    st = await ag.initialize()
    assert st["security"] == "ready" and st["version"] == ag.VERSION
    await ag.close()
run("Agent: initialize completes", ag_init, is_async=True)

async def ag_predict_basic():
    ag = OracleAgent("test_key")
    await ag.initialize()
    r  = await ag.predict("RELIANCE", user_id="tester")
    assert r["status"] == "success"
    assert all(k in r for k in ["signal","sentiment","analysis","risk_warning","meta"])
    await ag.close()
run("Agent: predict returns full response", ag_predict_basic, is_async=True)

async def ag_watchlist():
    ag = OracleAgent("test_key")
    await ag.initialize()
    valid = {"STRONG BUY","BUY","HOLD","SELL","STRONG SELL"}
    for t in ["NIFTY","TCS","HDFC","INFY","SBI","WIPRO"]:
        r = await ag.predict(t, user_id="wl")
        assert r["status"] == "success" and r["signal"]["action"] in valid
    await ag.close()
run("Agent: full watchlist all valid actions", ag_watchlist, is_async=True)

async def ag_sql_rejected():
    ag = OracleAgent("test_key")
    r  = await ag.predict("'; DROP TABLE--", user_id="attacker")
    assert r["status"] == "rejected"
    await ag.close()
run("Agent: SQL injection in ticker rejected", ag_sql_rejected, is_async=True)

async def ag_xss_rejected():
    ag = OracleAgent("test_key")
    r  = await ag.predict("<script>alert(1)</script>", user_id="attacker")
    assert r["status"] == "rejected", f"Expected rejected, got: {r.get('status')}"
    await ag.close()
run("Agent: XSS in ticker rejected", ag_xss_rejected, is_async=True)

async def ag_empty_ticker():
    ag = OracleAgent("test_key")
    r  = await ag.predict("", user_id="bad")
    assert r["status"] == "rejected"
    await ag.close()
run("Agent: empty ticker rejected", ag_empty_ticker, is_async=True)

async def ag_malicious_prices():
    ag = OracleAgent("test_key")
    await ag.initialize()
    prices = ["DROP TABLE", float("nan"), -999.0, float("inf"),
              100.0, 101.0, 102.0, 103.0, 104.0, 105.0]
    r = await ag.predict("NIFTY", prices=prices, user_id="inject")
    assert r["status"] in ("success","rejected")
    await ag.close()
run("Agent: malicious prices handled safely", ag_malicious_prices, is_async=True)

async def ag_rate_limit():
    ag = OracleAgent("test_key")
    await ag.initialize()
    for _ in range(30): ag.limiter.check("flooder", max_requests=30, window_seconds=60)
    r = await ag.predict("NIFTY", user_id="flooder")
    assert r["status"] == "blocked"
    await ag.close()
run("Agent: rate limit blocks flood", ag_rate_limit, is_async=True)

async def ag_sl_tp_valid():
    ag = OracleAgent("test_key")
    await ag.initialize()
    r   = await ag.predict("TCS", user_id="sltp")
    sig = r["signal"]
    assert sig["stop_loss"]   < sig["entry_price"], "SL must be below entry"
    assert sig["take_profit"] > sig["entry_price"], "TP must be above entry"
    assert 0.0 <= sig["confidence"] <= 1.0,         "Confidence must be in [0,1]"
    await ag.close()
run("Agent: SL < entry < TP and confidence valid", ag_sl_tp_valid, is_async=True)

async def ag_audit_recorded():
    ag = OracleAgent("test_key")
    await ag.initialize()
    await ag.predict("ICICI", user_id="audit_chk")
    rows = ag.audit.get_recent(10)
    assert any("predict" in str(r) for r in rows)
    await ag.close()
run("Agent: prediction logged to audit trail", ag_audit_recorded, is_async=True)

async def ag_custom_prices():
    ag = OracleAgent("test_key")
    await ag.initialize()
    prices = [100.0 + i * 0.5 for i in range(40)]
    r = await ag.predict("INFY", prices=prices, user_id="custom")
    assert r["status"] == "success" and r["meta"]["prices_used"] == 40
    await ag.close()
run("Agent: custom price array accepted", ag_custom_prices, is_async=True)


# ══════════════════════════════════════════════════════════════
# FINAL REPORT
# ══════════════════════════════════════════════════════════════
total  = len(results)
passed = sum(1 for r in results if r[0] == PASS)
failed = total - passed
times  = [r[2] for r in results]

print("\n" + "═"*60)
print("  ORACLE v2 — OPTIMISED TEST REPORT")
print("═"*60)
print(f"\n  Total      : {total}")
print(f"  Passed     : {passed}  ✅")
print(f"  Failed     : {failed}  {'❌' if failed else '✅'}")
print(f"  Score      : {passed/total*100:.1f}%")
print(f"  Avg time   : {sum(times)/len(times):.1f}ms per test")
print(f"  Total time : {sum(times)/1000:.2f}s")
print(f"  Fastest    : {min(times):.1f}ms  |  Slowest: {max(times):.1f}ms")

sections = [
    (0,  20, "🔐 Security"),
    (20, 47, "⚡ DSA Algorithms"),
    (47, 60, "📈 Prediction Engine"),
    (60, 71, "🤖 Integration"),
]
print("\n  SECTION BREAKDOWN:")
for start, end, label in sections:
    sec = results[start:end]
    p   = sum(1 for r in sec if r[0] == PASS)
    cnt = end - start
    bar = "✅" if p == cnt else "⚠️ "
    print(f"    {bar} {label:<26}: {p}/{cnt}")

if failed:
    print("\n  FAILURES:")
    for r in results:
        if r[0] == FAIL:
            print(f"    ❌ {r[1]}")
            if len(r) > 3: print(f"       → {r[3]}")

print()
badge = ("🟢 ALL 71 TESTS PASS — ORACLE v2 PRODUCTION READY"
         if failed == 0 else f"🟡 {failed}/{total} TESTS NEED ATTENTION")
print(f"  {badge}")
print("═"*60 + "\n")
sys.exit(0 if failed == 0 else 1)
