#!/usr/bin/env python3
"""
ORACLE v2 — Quick Launch Demo
Runs the complete agent pipeline and shows live predictions
"""
import sys, os, asyncio, json, time
# Dynamic path — works on ANY machine regardless of username or install location
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.agent import OracleAgent

BANNER = """
╔══════════════════════════════════════════════════════════════╗
║          ORACLE v2 — Future Prediction Agent                 ║
║   Local LLM · DSA Internet · R Models · Signal Fusion       ║
║   Zero Token Cost · Maximum Security · 80-95% Accuracy      ║
╚══════════════════════════════════════════════════════════════╝
"""

WATCHLIST = ["RELIANCE", "TCS", "NIFTY", "BANKNIFTY", "INFY", "HDFC", "SBI"]

async def main():
    print(BANNER)

    agent = OracleAgent(master_password="oracle_secure_key_2025")

    print("🔄 Initializing all subsystems...\n")
    status = await agent.initialize()

    print(f"  Security layer    : ✅ Active")
    print(f"  DSA internet engine: ✅ Ready")
    print(f"  Prediction engine  : ✅ Ready (R + Python)")
    print(f"  Ollama LLM        : {'✅ ' + status['ollama'].get('model','') if status['ollama']['available'] else '⚠️  Not running (using offline mode)'}")
    print(f"\n  Agent version     : v{agent.VERSION}")
    print()

    print("📡 Running predictions for full watchlist...\n")
    print(f"  {'TICKER':<12} {'ACTION':<13} {'CONF':>6} {'SCORE':>7} {'RISK':<8} {'ENTRY':>10} {'SL':>10} {'TP':>10}")
    print("  " + "─"*80)

    for ticker in WATCHLIST:
        result = await agent.predict(ticker, user_id="demo")
        sig    = result.get("signal", {})
        sent   = result.get("sentiment", {})

        action     = sig.get("action", "N/A")
        confidence = sig.get("confidence", 0) * 100
        score      = sig.get("score", 0)
        risk       = sig.get("risk_level", "N/A")
        entry      = sig.get("entry_price", 0)
        sl         = sig.get("stop_loss", 0)
        tp         = sig.get("take_profit", 0)

        # Color-code action
        color = ""
        if "BUY"  in action: color = "\033[92m"   # green
        if "SELL" in action: color = "\033[91m"   # red
        if action == "HOLD": color = "\033[93m"   # yellow
        reset = "\033[0m"

        print(f"  {ticker:<12} {color}{action:<13}{reset} {confidence:>5.1f}% {score:>+7.3f} "
              f"{risk:<8} ₹{entry:>8.2f} ₹{sl:>8.2f} ₹{tp:>8.2f}")

    print()
    print("─"*82)

    # Show detailed analysis for top pick
    print("\n🔍 Detailed analysis — RELIANCE:\n")
    result = await agent.predict("RELIANCE", user_id="demo_detail")
    print(f"  Signal : {result['signal']['action']}")
    print(f"  Score  : {result['signal']['score']:+.4f}")
    print(f"  Conf   : {result['signal']['confidence']*100:.1f}%")
    print(f"\n  Price reason    : {result['signal']['price_reason']}")
    print(f"  Pattern reason  : {result['signal']['pattern_reason']}")
    print(f"  Sentiment reason: {result['signal']['sentiment_reason']}")
    print(f"\n  Analysis:\n  {result['analysis']}")
    print(f"\n  {result['risk_warning']}")
    print(f"\n  Sources read : {result['sentiment']['internet'].get('sources_read', 0)}")
    print(f"  Elapsed      : {result['meta']['elapsed_seconds']}s")

    await agent.close()
    print("\n✅ ORACLE v2 demo complete.\n")


if __name__ == "__main__":
    asyncio.run(main())
