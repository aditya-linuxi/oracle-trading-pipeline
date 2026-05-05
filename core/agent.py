"""
ORACLE v2 — Main Agent Orchestrator
Ties together: Security · Internet Engine · Ollama LLM · Prediction Engine
One call → full prediction pipeline
"""
import asyncio, time, json, math, random
from typing import Optional
import sys, os
# Dynamic — resolves to oracle_v2/ root on any machine
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from security.security       import KeyVault, RateLimiter, InputSanitizer, AuditLogger
from core.internet_engine    import InternetEngine, TickBuffer
from core.ollama_client      import OllamaClient
from models.prediction_engine import SignalFusion, FinalSignal


# ─── ORACLE AGENT ─────────────────────────────────────────────────────────────

class OracleAgent:
    """
    World's most powerful autonomous prediction agent.
    Architecture:
      Internet Engine (DSA) → sentiment data
      Ollama LLM            → NLP sentiment scoring
      R / Python models     → price signal
      Signal Fusion         → final trading decision
      Security Layer        → auth, rate limiting, audit
    """

    VERSION = "2.0.0"

    def __init__(self, master_password: str = "oracle_dev_key"):
        # Security
        self.vault    = KeyVault(master_password)
        self.limiter  = RateLimiter()
        self.sanitize = InputSanitizer()
        self.audit    = AuditLogger()

        # Core engines
        self.internet = InternetEngine()
        self.ollama   = OllamaClient()
        self.fusion   = SignalFusion()

        # State
        self._tick_buffers: dict[str, TickBuffer] = {}
        self._initialized  = False
        self._ollama_ready = False

        self.audit.log("SYSTEM", "OracleAgent.__init__", "SUCCESS",
                       details=f"v{self.VERSION}")

    async def initialize(self) -> dict:
        """Boot sequence — check all subsystems"""
        status = {}

        # Check Ollama
        ollama_status = await self.ollama.check_availability()
        self._ollama_ready = ollama_status["available"]
        status["ollama"] = ollama_status

        # Check internet engine
        status["internet_engine"] = "ready"
        status["security"]        = "ready"
        status["prediction_engine"]= "ready"
        status["version"]         = self.VERSION

        self._initialized = True
        self.audit.log("SYSTEM", "initialize", "SUCCESS",
                       details=json.dumps(status))
        return status

    def _get_tick_buffer(self, ticker: str) -> TickBuffer:
        if ticker not in self._tick_buffers:
            self._tick_buffers[ticker] = TickBuffer(window_size=60)
        return self._tick_buffers[ticker]

    def _simulate_prices(self, ticker: str, n: int = 60) -> list[float]:
        """
        Simulates realistic price data for demo/testing.
        In production: replace with live Zerodha Kite / Yahoo Finance API.
        """
        random.seed(hash(ticker) % 10000)
        base_prices = {
            "RELIANCE": 2850.0, "TCS": 3980.0, "INFY": 1720.0,
            "NIFTY": 22500.0,   "BANKNIFTY": 48200.0, "HDFC": 1620.0,
            "ICICI": 1095.0,    "SBI": 820.0,  "WIPRO": 465.0,
            "DEFAULT": 1000.0
        }
        base = base_prices.get(ticker.upper(), base_prices["DEFAULT"])
        prices = [base]
        for _ in range(n - 1):
            change = random.gauss(0, 0.008)  # 0.8% daily vol
            prices.append(round(prices[-1] * (1 + change), 2))
        return prices

    async def predict(
        self,
        ticker: str,
        prices: Optional[list[float]] = None,
        api_key: Optional[str] = None,
        user_id: str = "anonymous"
    ) -> dict:
        """
        Main prediction pipeline.
        Input:  ticker symbol, optional price array, auth
        Output: complete trading signal with analysis
        """

        # ── Security checks ──────────────────────────────────────────────────
        try:
            ticker = self.sanitize.sanitize_ticker(ticker)
        except ValueError as e:
            self.audit.log("SECURITY", "predict", "REJECTED",
                           user_id=user_id, details=str(e))
            return {"error": str(e), "status": "rejected"}

        if not self.limiter.check(user_id, max_requests=30, window_seconds=60):
            self.audit.log("SECURITY", "rate_limit", "BLOCKED", user_id=user_id)
            return {"error": "Rate limit exceeded. Try again in 5 minutes.", "status": "blocked"}

        # ── Initialize if needed ─────────────────────────────────────────────
        if not self._initialized:
            await self.initialize()

        t_start = time.time()

        # ── Step 1: Price data ───────────────────────────────────────────────
        if prices is None or len(prices) < 5:
            prices = self._simulate_prices(ticker)

        # Sanitize every price — reject strings, inf, nan, negatives
        clean_prices = []
        for p in prices[-100:]:
            try:
                clean_prices.append(
                    self.sanitize.sanitize_number(p, min_val=0.01, max_val=10_000_000)
                )
            except ValueError:
                # Skip bad values silently — log it
                self.audit.log("SECURITY", "bad_price_value", "SKIPPED",
                               user_id=user_id, details=str(p)[:50])

        if len(clean_prices) < 5:
            self.audit.log("SECURITY", "predict", "REJECTED",
                           user_id=user_id, details="Insufficient valid prices after sanitization")
            return {"error": "Insufficient valid price data provided.", "status": "rejected"}

        prices = clean_prices

        # ── Step 2: Internet sentiment (DSA engine) ──────────────────────────
        internet_sentiment = {"score": 0.0, "sentiment": "NEUTRAL", "sources_read": 0}
        try:
            internet_sentiment = await self.internet.get_market_sentiment(ticker)
        except Exception:
            pass

        # ── Step 3: LLM sentiment (Ollama) ──────────────────────────────────
        llm_sentiment = {"score": 0.0, "direction": "NEUTRAL"}
        if self._ollama_ready and internet_sentiment.get("keywords"):
            kw_text = " ".join(internet_sentiment.get("keywords", []))
            try:
                llm_sentiment = await self.ollama.get_sentiment(kw_text, ticker)
            except Exception:
                pass

        # Blend DSA + LLM sentiment
        combined_sentiment = (
            internet_sentiment["score"] * 0.5 +
            llm_sentiment["score"]      * 0.5
        )

        # ── Step 4: Signal fusion (R + LSTM + sentiment) ─────────────────────
        signal = self.fusion.compute(
            prices=prices,
            sentiment_score=combined_sentiment,
            ticker=ticker
        )

        # ── Step 5: LLM explanation ──────────────────────────────────────────
        analysis_text = ""
        if self._ollama_ready:
            try:
                analysis_text = await self.ollama.analyze_market(
                    ticker=ticker,
                    price_data={
                        "current_price": signal.entry_price,
                        "rsi":  signal.price_reason,
                        "macd": "computed",
                        "volatility": "computed",
                        "signal": signal.action
                    },
                    sentiment={"direction": internet_sentiment["sentiment"],
                               "score": combined_sentiment,
                               "keywords": internet_sentiment.get("keywords", [])}
                )
            except Exception:
                pass

        elapsed = round(time.time() - t_start, 3)

        # ── Build response ────────────────────────────────────────────────────
        response = {
            "status":   "success",
            "ticker":   ticker,
            "signal":   self.fusion.to_dict(signal),
            "sentiment": {
                "internet": internet_sentiment,
                "llm":      llm_sentiment,
                "combined": round(combined_sentiment, 4)
            },
            "analysis": analysis_text or (
                f"{ticker}: {signal.action} signal with "
                f"{signal.confidence*100:.1f}% confidence. "
                f"Entry ₹{signal.entry_price:.2f}, "
                f"SL ₹{signal.stop_loss:.2f}, "
                f"TP ₹{signal.take_profit:.2f}. "
                f"Risk: {signal.risk_level}."
            ),
            "risk_warning": (
                "⚠️ This is a model-generated signal, not financial advice. "
                "Always use stop-losses. Never risk more than you can afford to lose."
            ),
            "meta": {
                "elapsed_seconds": elapsed,
                "prices_used":     len(prices),
                "ollama_active":   self._ollama_ready,
                "oracle_version":  self.VERSION
            }
        }

        self.audit.log("PREDICT", f"predict:{ticker}", "SUCCESS",
                       user_id=user_id,
                       details=f"action={signal.action} conf={signal.confidence:.2f}")
        return response

    async def run_autonomous_loop(self, tickers: list[str],
                                  interval_seconds: int = 60):
        """
        24/7 autonomous monitoring loop.
        Runs forever — predicts all tickers every interval seconds.
        """
        print(f"[ORACLE] Autonomous loop started for: {tickers}")
        print(f"[ORACLE] Interval: {interval_seconds}s | Press Ctrl+C to stop\n")

        cycle = 0
        while True:
            cycle += 1
            print(f"─── Cycle #{cycle} @ {time.strftime('%H:%M:%S')} ───")
            for ticker in tickers:
                result = await self.predict(ticker, user_id="autonomous")
                sig    = result.get("signal", {})
                print(
                    f"  {ticker:12s} │ {sig.get('action','N/A'):11s} │ "
                    f"Conf: {sig.get('confidence',0)*100:5.1f}% │ "
                    f"Score: {sig.get('score',0):+.3f} │ "
                    f"Risk: {sig.get('risk_level','N/A')}"
                )
            print()
            await asyncio.sleep(interval_seconds)

    async def close(self):
        await self.internet.close()
        await self.ollama.close()
        self.audit.log("SYSTEM", "shutdown", "SUCCESS")
