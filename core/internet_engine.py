"""
ORACLE v2 — DSA-Powered Internet Data Engine
Trie · Parallel BFS Crawler · Bloom Filter · Max-Heap · Sliding Window · KMP
Reads the entire financial internet in seconds.
"""
import asyncio, aiohttp, hashlib, heapq, time, re, json
from collections import defaultdict, deque
from typing import Optional
import urllib.parse


# ─── BLOOM FILTER — O(1) duplicate detection ─────────────────────────────────

class BloomFilter:
    def __init__(self, capacity: int = 1_000_000, error_rate: float = 0.001):
        import math
        # m = -n * ln(p) / (ln2)^2
        ln2_sq = math.log(2) ** 2
        m = int(-capacity * math.log(error_rate) / ln2_sq)
        self.size = max(m, 8)
        self.bits = bytearray(self.size // 8 + 1)
        self.num_hashes = max(1, int((self.size / capacity) * math.log(2)))

    def _hashes(self, item: str):
        for i in range(self.num_hashes):
            h = int(hashlib.md5(f"{item}{i}".encode()).hexdigest(), 16)
            yield h % self.size

    def add(self, item: str):
        for idx in self._hashes(item):
            self.bits[idx // 8] |= (1 << (idx % 8))

    def __contains__(self, item: str) -> bool:
        return all(
            self.bits[idx // 8] & (1 << (idx % 8))
            for idx in self._hashes(item)
        )


# ─── TRIE — O(L) keyword indexing ─────────────────────────────────────────────

class TrieNode:
    __slots__ = ["children", "is_end", "metadata"]
    def __init__(self):
        self.children: dict = {}
        self.is_end: bool = False
        self.metadata: dict = {}

class FinancialTrie:
    """Indexes all financial keywords for instant O(L) lookup"""

    KEYWORDS = [
        "bullish", "bearish", "breakout", "support", "resistance",
        "volume surge", "buy signal", "sell signal", "earnings beat",
        "earnings miss", "rate hike", "rate cut", "gdp growth", "inflation",
        "recession", "profit", "loss", "revenue", "acquisition", "merger",
        "ipo", "dividend", "bonus share", "stock split", "buyback",
        "fii buying", "fii selling", "dii buying", "circuit breaker",
        "upper circuit", "lower circuit", "delivery percentage",
        "nifty", "sensex", "banknifty", "reliance", "tcs", "infosys",
        "hdfc", "icici", "sbi", "wipro", "hcl", "bajaj", "adani",
        "crude oil", "usd inr", "gold", "silver", "bitcoin"
    ]

    def __init__(self):
        self.root = TrieNode()
        self.sentiment_scores = {
            "bullish": 0.8, "breakout": 0.7, "buy signal": 0.9,
            "earnings beat": 0.85, "profit": 0.6, "revenue": 0.4,
            "dividend": 0.5, "fii buying": 0.7, "upper circuit": 0.9,
            "bearish": -0.8, "sell signal": -0.9, "earnings miss": -0.85,
            "loss": -0.6, "recession": -0.7, "fii selling": -0.7,
            "lower circuit": -0.9, "circuit breaker": -0.5,
        }
        for word in self.KEYWORDS:
            self.insert(word, {"score": self.sentiment_scores.get(word, 0.0)})

    def insert(self, word: str, metadata: dict = {}):
        node = self.root
        for ch in word.lower():
            if ch not in node.children:
                node.children[ch] = TrieNode()
            node = node.children[ch]
        node.is_end = True
        node.metadata = metadata

    def search_in_text(self, text: str) -> list[dict]:
        """Find ALL financial keywords in text — O(n*L) worst case"""
        text_lower = text.lower()
        findings = []
        for i in range(len(text_lower)):
            node = self.root
            for j in range(i, len(text_lower)):
                ch = text_lower[j]
                if ch not in node.children:
                    break
                node = node.children[ch]
                if node.is_end:
                    keyword = text_lower[i:j+1]
                    findings.append({
                        "keyword": keyword,
                        "position": i,
                        "score": node.metadata.get("score", 0.0)
                    })
        return findings


# ─── KMP STRING SEARCH — O(n+m) pattern matching ─────────────────────────────

class KMPSearch:
    @staticmethod
    def build_failure(pattern: str) -> list:
        f = [0] * len(pattern)
        j = 0
        for i in range(1, len(pattern)):
            while j > 0 and pattern[i] != pattern[j]:
                j = f[j-1]
            if pattern[i] == pattern[j]:
                j += 1
            f[i] = j
        return f

    @staticmethod
    def search(text: str, pattern: str) -> list[int]:
        if not pattern or not text:
            return []
        failure = KMPSearch.build_failure(pattern)
        matches, j = [], 0
        for i, ch in enumerate(text):
            while j > 0 and ch != pattern[j]:
                j = failure[j-1]
            if ch == pattern[j]:
                j += 1
            if j == len(pattern):
                matches.append(i - j + 1)
                j = failure[j-1]
        return matches


# ─── SLIDING WINDOW RING BUFFER — O(1) tick updates ─────────────────────────

class TickBuffer:
    """Maintains rolling OHLCV windows in O(1) per update"""

    def __init__(self, window_size: int = 60):
        self.window = deque(maxlen=window_size)
        self.size = window_size

    def push(self, tick: dict):
        self.window.append({**tick, "ts": time.time()})

    def get_window(self) -> list:
        return list(self.window)

    def latest_close(self) -> Optional[float]:
        if self.window:
            return self.window[-1].get("close")
        return None

    def sma(self) -> Optional[float]:
        closes = [t["close"] for t in self.window if "close" in t]
        return sum(closes) / len(closes) if closes else None

    def rsi(self, period: int = 14) -> Optional[float]:
        closes = [t["close"] for t in self.window if "close" in t]
        if len(closes) < period + 1:
            return None
        gains, losses = [], []
        for i in range(1, len(closes)):
            d = closes[i] - closes[i-1]
            gains.append(max(d, 0))
            losses.append(max(-d, 0))
        ag = sum(gains[-period:]) / period
        al = sum(losses[-period:]) / period
        if al == 0 and ag == 0:
            return 50.0   # flat market — neutral RSI
        if al == 0:
            return 100.0
        rs = ag / al
        return round(100 - (100 / (1 + rs)), 2)


# ─── MAX-HEAP PRIORITY QUEUE — O(log n) signal ranking ──────────────────────

class SignalHeap:
    """Surfaces highest-priority, freshest signals first"""

    def __init__(self):
        self._heap: list = []
        self._counter = 0

    def push(self, score: float, item: dict):
        heapq.heappush(self._heap, (-score, self._counter, item))
        self._counter += 1

    def pop(self) -> Optional[dict]:
        if self._heap:
            _, _, item = heapq.heappop(self._heap)
            return item
        return None

    def peek_top(self, n: int = 5) -> list:
        return [item for _, _, item in heapq.nsmallest(n, self._heap)]

    def __len__(self):
        return len(self._heap)


# ─── PARALLEL BFS WEB CRAWLER ─────────────────────────────────────────────────

FINANCIAL_SOURCES = [
    "https://finance.yahoo.com/news/",
    "https://economictimes.indiatimes.com/markets/stocks/news",
    "https://www.moneycontrol.com/news/business/markets/",
    "https://www.reuters.com/business/finance/",
]

RSS_FEEDS = [
    "https://economictimes.indiatimes.com/markets/rss.cms",
    "https://www.moneycontrol.com/rss/marketreports.xml",
]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; OracleBot/2.0; research)",
    "Accept": "text/html,application/xhtml+xml",
    "Accept-Language": "en-US,en;q=0.9",
}

class InternetEngine:
    """
    God-tier internet reading engine.
    BFS crawler + Bloom dedup + Trie extraction + Heap ranking
    """

    def __init__(self):
        self.bloom = BloomFilter()
        self.trie  = FinancialTrie()
        self.heap  = SignalHeap()
        self.kmp   = KMPSearch()
        self._session: Optional[aiohttp.ClientSession] = None

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            timeout = aiohttp.ClientTimeout(total=10)
            self._session = aiohttp.ClientSession(
                headers=HEADERS, timeout=timeout
            )
        return self._session

    async def fetch_page(self, url: str) -> str:
        """Fetch a single page — returns text or empty string"""
        if url in self.bloom:
            return ""
        self.bloom.add(url)
        try:
            session = await self._get_session()
            async with session.get(url, ssl=False) as resp:
                if resp.status == 200:
                    ct = resp.headers.get("content-type", "")
                    if "text" in ct or "xml" in ct:
                        return await resp.text(errors="ignore")
        except Exception:
            pass
        return ""

    def extract_text(self, html: str) -> str:
        """Strip HTML tags — get raw text"""
        clean = re.sub(r"<[^>]+>", " ", html)
        clean = re.sub(r"\s+", " ", clean)
        return clean[:5000]

    def score_text(self, text: str, ticker: str = "") -> dict:
        """Score text using Trie keyword extraction"""
        if not text or not isinstance(text, str) or not text.strip():
            return {"score": 0.0, "keywords": [], "signal": "NEUTRAL", "count": 0}
        findings = self.trie.search_in_text(text)
        if not findings:
            return {"score": 0.0, "keywords": [], "signal": "NEUTRAL", "count": 0}

        total_score = sum(f["score"] for f in findings)
        avg_score   = total_score / len(findings)
        keywords    = list({f["keyword"] for f in findings})

        # Boost if ticker mentioned
        if ticker and self.kmp.search(text.lower(), ticker.lower()):
            avg_score *= 1.3

        signal = (
            "STRONG_BULLISH" if avg_score >  0.7 else
            "BULLISH"        if avg_score >  0.3 else
            "STRONG_BEARISH" if avg_score < -0.7 else
            "BEARISH"        if avg_score < -0.3 else
            "NEUTRAL"
        )
        return {
            "score":    round(min(max(avg_score, -1.0), 1.0), 4),
            "keywords": keywords[:10],
            "signal":   signal,
            "count":    len(findings)
        }

    async def crawl_sources(self, ticker: str = "", max_pages: int = 10) -> list[dict]:
        """BFS parallel crawl of all financial sources"""
        tasks = [self.fetch_page(url) for url in (FINANCIAL_SOURCES + RSS_FEEDS)[:max_pages]]
        pages = await asyncio.gather(*tasks, return_exceptions=True)

        results = []
        for url, page in zip(FINANCIAL_SOURCES + RSS_FEEDS, pages):
            if isinstance(page, str) and len(page) > 100:
                text = self.extract_text(page)
                scored = self.score_text(text, ticker)
                scored["source"] = url
                scored["timestamp"] = time.time()
                self.heap.push(abs(scored["score"]), scored)
                results.append(scored)

        return results

    async def get_market_sentiment(self, ticker: str = "NIFTY") -> dict:
        """Main entry: crawl internet, return aggregated sentiment"""
        results = await self.crawl_sources(ticker=ticker, max_pages=8)

        if not results:
            return {"sentiment": "NEUTRAL", "score": 0.0, "sources": 0}

        scores  = [r["score"] for r in results]
        avg     = sum(scores) / len(scores)
        top     = self.heap.peek_top(3)

        return {
            "sentiment":    "BULLISH" if avg > 0 else "BEARISH" if avg < 0 else "NEUTRAL",
            "score":        round(avg, 4),
            "sources_read": len(results),
            "top_signals":  top,
            "keywords":     list({kw for r in results for kw in r.get("keywords", [])}),
            "timestamp":    time.time()
        }

    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()
            self._session = None
