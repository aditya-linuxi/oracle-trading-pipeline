"""
ORACLE v2 — Ollama Local LLM Client
Zero token cost · Zero rate limit · Runs on your machine
Sentiment extraction · Market reasoning · Pattern explanation
"""
import aiohttp, asyncio, json, re, time
from typing import Optional


OLLAMA_BASE = "http://localhost:11434"
DEFAULT_MODEL = "deepseek-r1"
FALLBACK_MODELS = ["mistral", "llama3.1", "phi3", "qwen2.5"]


# ─── OLLAMA CLIENT ────────────────────────────────────────────────────────────

class OllamaClient:
    """
    Async client for local Ollama LLM.
    Handles: sentiment, market analysis, signal explanation, Q&A
    """

    def __init__(self, base_url: str = OLLAMA_BASE):
        self.base_url     = base_url.rstrip("/")
        self._model       = DEFAULT_MODEL
        self._available   = False
        self._session: Optional[aiohttp.ClientSession] = None

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=60)
            )
        return self._session

    async def check_availability(self) -> dict:
        """Ping Ollama — returns available models"""
        try:
            session = await self._get_session()
            async with session.get(f"{self.base_url}/api/tags") as resp:
                if resp.status == 200:
                    data   = await resp.json()
                    models = [m["name"] for m in data.get("models", [])]
                    # Pick best available model
                    for preferred in [DEFAULT_MODEL] + FALLBACK_MODELS:
                        for m in models:
                            if preferred in m:
                                self._model     = m
                                self._available = True
                                return {"available": True, "model": m, "all_models": models}
                    if models:
                        self._model     = models[0]
                        self._available = True
                        return {"available": True, "model": models[0], "all_models": models}
        except Exception as e:
            pass
        self._available = False
        return {"available": False, "model": None, "all_models": []}

    async def generate(self, prompt: str, system: str = "", model: str = "") -> str:
        """Raw generation — returns full response text"""
        if not self._available:
            return self._offline_response(prompt)

        payload = {
            "model":  model or self._model,
            "prompt": prompt,
            "stream": False,
        }
        if system:
            payload["system"] = system

        try:
            session = await self._get_session()
            async with session.post(
                f"{self.base_url}/api/generate",
                json=payload
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return data.get("response", "").strip()
        except Exception as e:
            pass
        return self._offline_response(prompt)

    def _offline_response(self, prompt: str) -> str:
        """Fallback when Ollama not running — keyword-based sentiment"""
        bullish_words = ["profit", "growth", "beat", "surge", "rally", "buy",
                         "bullish", "breakout", "positive", "strong", "gain"]
        bearish_words = ["loss", "miss", "fall", "decline", "sell", "bearish",
                         "crash", "weak", "negative", "drop", "concern"]
        prompt_lower  = prompt.lower()
        bull_count    = sum(1 for w in bullish_words if w in prompt_lower)
        bear_count    = sum(1 for w in bearish_words if w in prompt_lower)
        if bull_count > bear_count:
            return "BULLISH | Score: +0.60 | [offline-keyword-model]"
        elif bear_count > bull_count:
            return "BEARISH | Score: -0.60 | [offline-keyword-model]"
        return "NEUTRAL | Score: 0.00 | [offline-keyword-model]"


    # ─── SPECIALISED PROMPTS ─────────────────────────────────────────────────

    async def get_sentiment(self, text: str, ticker: str = "") -> dict:
        """
        Extract sentiment from news/social text.
        Returns: direction, score, keywords, confidence
        """
        system = (
            "You are a senior quantitative financial analyst. "
            "Respond ONLY in this exact JSON format, nothing else:\n"
            '{"direction":"BULLISH|BEARISH|NEUTRAL","score":0.00,"keywords":[],"reasoning":""}'
        )
        prompt = (
            f"Analyze the market sentiment of this text"
            f"{f' regarding stock {ticker}' if ticker else ''}.\n"
            f"Score range: -1.0 (very bearish) to +1.0 (very bullish).\n\n"
            f"Text: {text[:2000]}"
        )
        raw = await self.generate(prompt, system=system)

        # Parse JSON response
        try:
            match = re.search(r'\{[^{}]+\}', raw, re.DOTALL)
            if match:
                data = json.loads(match.group())
                return {
                    "direction":  data.get("direction", "NEUTRAL"),
                    "score":      float(data.get("score", 0.0)),
                    "keywords":   data.get("keywords", []),
                    "reasoning":  data.get("reasoning", ""),
                    "raw":        raw[:500],
                    "model":      self._model,
                    "timestamp":  time.time()
                }
        except Exception:
            pass

        # Fallback parse from raw text
        direction = "NEUTRAL"
        score     = 0.0
        if "BULLISH" in raw.upper():
            direction = "BULLISH"
            score_match = re.search(r'[+]?(\d+\.?\d*)', raw)
            score = float(score_match.group()) if score_match else 0.6
        elif "BEARISH" in raw.upper():
            direction = "BEARISH"
            score_match = re.search(r'-(\d+\.?\d*)', raw)
            score = -float(score_match.group()) if score_match else -0.6

        return {
            "direction": direction,
            "score":     round(max(-1.0, min(1.0, score)), 4),
            "keywords":  [],
            "reasoning": raw[:200],
            "model":     self._model,
            "timestamp": time.time()
        }

    async def analyze_market(self, ticker: str, price_data: dict,
                              sentiment: dict) -> str:
        """Full market analysis — plain language explanation"""
        system = (
            "You are ORACLE, the world's best quantitative trading AI. "
            "Give a concise, confident analysis in 3-4 sentences. "
            "Include: trend direction, key levels, risk factors, recommendation."
        )
        prompt = (
            f"Stock: {ticker}\n"
            f"Current price: {price_data.get('current_price', 'N/A')}\n"
            f"RSI: {price_data.get('rsi', 'N/A')}\n"
            f"MACD: {price_data.get('macd', 'N/A')}\n"
            f"Volatility: {price_data.get('volatility', 'N/A')}\n"
            f"Price signal: {price_data.get('signal', 'N/A')}\n"
            f"Market sentiment: {sentiment.get('direction', 'N/A')} "
            f"(score: {sentiment.get('score', 0.0):+.2f})\n"
            f"Top keywords: {', '.join(sentiment.get('keywords', [])[:5])}\n\n"
            f"Provide analysis and trading recommendation."
        )
        return await self.generate(prompt, system=system)

    async def explain_signal(self, signal: dict) -> str:
        """Explain a trading signal in plain language"""
        system = "You are a trading coach. Explain in simple, clear language for a retail trader."
        prompt = (
            f"Explain this trading signal:\n"
            f"Action: {signal.get('action')}\n"
            f"Confidence: {signal.get('confidence', 0)*100:.1f}%\n"
            f"Entry: {signal.get('entry_price')}\n"
            f"Stop Loss: {signal.get('stop_loss')}\n"
            f"Take Profit: {signal.get('take_profit')}\n"
            f"Price Reason: {signal.get('price_reason')}\n"
            f"Pattern Reason: {signal.get('pattern_reason')}\n"
            f"Sentiment Reason: {signal.get('sentiment_reason')}\n\n"
            f"Explain what this means, what to do, and what risks to watch."
        )
        return await self.generate(prompt, system=system)

    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()
            self._session = None
