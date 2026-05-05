# ============================================================
# ORACLE v2 — Production R Prediction & Forecasting Script
# Primary language for all statistical modeling
# Run: Rscript oracle_predict.R RELIANCE 60
# ============================================================

suppressPackageStartupMessages({
  library(jsonlite)
})

# ── Arguments ─────────────────────────────────────────────────
args   <- commandArgs(trailingOnly = TRUE)
ticker <- if (length(args) >= 1) toupper(args[1]) else "NIFTY"
n_days <- if (length(args) >= 2) as.integer(args[2]) else 30

cat("=======================================================\n")
cat(sprintf("  ORACLE v2 — R Prediction Engine\n"))
cat(sprintf("  Ticker: %s | Forecast horizon: %d days\n", ticker, n_days))
cat("=======================================================\n\n")

# ── Simulate price data (replace with live API in production) ─
set.seed(as.integer(chartr("ABCDEFGHIJKLMNOPQRSTUVWXYZ",
                            "12345678901234567890123456", 
                            substr(ticker, 1, 1))) %% 1000)

base_price <- switch(ticker,
  "RELIANCE"  = 2850.0,
  "TCS"       = 3980.0,
  "INFY"      = 1720.0,
  "NIFTY"     = 22500.0,
  "BANKNIFTY" = 48200.0,
  "HDFC"      = 1620.0,
  "ICICI"     = 1095.0,
  "SBI"       = 820.0,
  "WIPRO"     = 465.0,
  1000.0
)

# Generate 200 days of simulated OHLCV (Geometric Brownian Motion)
n_hist <- 200
mu     <- 0.0003     # daily drift
sigma  <- 0.015      # daily volatility

set.seed(42)
returns <- rnorm(n_hist, mean = mu, sd = sigma)
closes  <- cumprod(c(base_price, exp(returns)))
closes  <- closes[-1]
dates   <- seq(Sys.Date() - n_hist + 1, Sys.Date(), by = "day")

price_data <- data.frame(
  date  = dates,
  close = round(closes, 2),
  open  = round(closes * (1 + rnorm(n_hist, 0, 0.003)), 2),
  high  = round(closes * (1 + abs(rnorm(n_hist, 0, 0.008))), 2),
  low   = round(closes * (1 - abs(rnorm(n_hist, 0, 0.008))), 2),
  volume= round(abs(rnorm(n_hist, 5e6, 1e6)))
)

# ── Technical Indicators ──────────────────────────────────────

# SMA
sma <- function(x, n) {
  stats::filter(x, rep(1/n, n), sides=1)
}

# EMA
ema <- function(x, n) {
  k <- 2 / (n + 1)
  e <- numeric(length(x))
  e[1] <- x[1]
  for (i in 2:length(x)) e[i] <- x[i] * k + e[i-1] * (1 - k)
  e
}

# RSI
rsi <- function(prices, period = 14) {
  changes <- diff(prices)
  gains   <- pmax(changes, 0)
  losses  <- pmax(-changes, 0)
  rsi_vals <- numeric(length(prices))
  rsi_vals[1:period] <- NA
  for (i in (period + 1):length(prices)) {
    ag <- mean(gains[(i - period):(i - 1)])
    al <- mean(losses[(i - period):(i - 1)])
    rsi_vals[i] <- if (al == 0) 100 else 100 - 100 / (1 + ag / al)
  }
  rsi_vals
}

# Bollinger Bands
bollinger <- function(prices, n = 20, k = 2) {
  mid   <- as.numeric(sma(prices, n))
  stdev <- zoo::rollapply(prices, n, sd, fill = NA, align = "right")
  list(upper = mid + k * stdev, mid = mid, lower = mid - k * stdev)
}

# MACD
macd <- function(prices, fast = 12, slow = 26, signal = 9) {
  macd_line   <- ema(prices, fast) - ema(prices, slow)
  signal_line <- ema(macd_line, signal)
  list(macd = macd_line, signal = signal_line,
       hist = macd_line - signal_line)
}

# Compute all indicators
prices_vec <- price_data$close
rsi_vals   <- rsi(prices_vec)
macd_vals  <- macd(prices_vec)
bb         <- tryCatch(bollinger(prices_vec), error = function(e) {
  list(upper = rep(NA, length(prices_vec)),
       mid   = rep(NA, length(prices_vec)),
       lower = rep(NA, length(prices_vec)))
})

current_price <- tail(prices_vec, 1)
current_rsi   <- tail(na.omit(rsi_vals), 1)
current_macd  <- tail(macd_vals$hist, 1)

cat(sprintf("Current Price : ₹%.2f\n", current_price))
cat(sprintf("RSI (14)      : %.2f %s\n",
    current_rsi,
    ifelse(current_rsi > 70, "[OVERBOUGHT]",
           ifelse(current_rsi < 30, "[OVERSOLD]", "[NEUTRAL]"))))
cat(sprintf("MACD Histogram: %+.4f %s\n",
    current_macd,
    ifelse(current_macd > 0, "[BULLISH]", "[BEARISH]")))

# ── Regime Detection (Hidden Markov Model approximation) ─────
# Simplified 3-state: BULL, BEAR, SIDEWAYS
recent_returns   <- diff(log(tail(prices_vec, 40)))
mean_ret         <- mean(recent_returns)
vol_ret          <- sd(recent_returns)
sharpe_approx    <- mean_ret / vol_ret * sqrt(252)

regime <- if (sharpe_approx > 1.0)  "BULL"
          else if (sharpe_approx < -1.0) "BEAR"
          else "SIDEWAYS"

cat(sprintf("Market Regime : %s (Sharpe≈%.2f)\n", regime, sharpe_approx))

# ── Linear Trend Model ────────────────────────────────────────
n_recent <- min(60, length(prices_vec))
recent   <- tail(prices_vec, n_recent)
x_seq    <- seq_len(n_recent)
lm_fit   <- lm(recent ~ x_seq)
slope    <- coef(lm_fit)[2]
r2       <- summary(lm_fit)$r.squared

cat(sprintf("Trend slope   : %+.4f (R²=%.3f)\n", slope, r2))

# ── Signal Generation ─────────────────────────────────────────
rsi_signal  <- if (current_rsi < 35) 0.8
               else if (current_rsi > 65) -0.8
               else (50 - current_rsi) / 50 * -1

macd_signal <- tanh(current_macd / (current_price * 0.001))
trend_signal<- tanh(slope / current_price * 1000)

final_score <- rsi_signal * 0.30 + macd_signal * 0.35 + trend_signal * 0.35
final_score <- max(-1, min(1, final_score))

action <- if (final_score >  0.65) "STRONG BUY"
          else if (final_score >  0.30) "BUY"
          else if (final_score < -0.65) "STRONG SELL"
          else if (final_score < -0.30) "SELL"
          else "HOLD"

confidence  <- abs(final_score) * 0.75 + 0.25

# ── Risk Management ───────────────────────────────────────────
stop_loss   <- round(current_price * 0.985, 2)   # 1.5% SL
take_profit <- round(current_price * 1.030, 2)   # 3.0% TP
vol_daily   <- sd(diff(log(tail(prices_vec, 30)))) * current_price
risk_level  <- if (vol_daily > current_price * 0.025) "HIGH"
               else if (vol_daily > current_price * 0.012) "MEDIUM"
               else "LOW"

# ── Simple ARIMA-like Forecast ────────────────────────────────
cat("\n--- FORECAST ---\n")

# Walk-forward using simple exponential smoothing
alpha   <- 0.3
smoothed <- prices_vec[1]
for (p in prices_vec[-1]) {
  smoothed <- alpha * p + (1 - alpha) * smoothed
}

# Project n_days ahead using drift + volatility bands
forecast_mean <- numeric(n_days)
forecast_lo80 <- numeric(n_days)
forecast_hi80 <- numeric(n_days)
forecast_lo95 <- numeric(n_days)
forecast_hi95 <- numeric(n_days)

for (i in seq_len(n_days)) {
  drift          <- smoothed * (1 + mu * i)
  std_err        <- smoothed * sigma * sqrt(i)
  forecast_mean[i] <- round(drift, 2)
  forecast_lo80[i] <- round(drift - 1.28 * std_err, 2)
  forecast_hi80[i] <- round(drift + 1.28 * std_err, 2)
  forecast_lo95[i] <- round(drift - 1.96 * std_err, 2)
  forecast_hi95[i] <- round(drift + 1.96 * std_err, 2)
}

cat(sprintf("Forecast +%d days:\n", n_days))
cat(sprintf("  Point estimate : ₹%.2f\n", tail(forecast_mean, 1)))
cat(sprintf("  80%% CI         : ₹%.2f – ₹%.2f\n",
            tail(forecast_lo80, 1), tail(forecast_hi80, 1)))
cat(sprintf("  95%% CI         : ₹%.2f – ₹%.2f\n",
            tail(forecast_lo95, 1), tail(forecast_hi95, 1)))

# ── Output Full JSON Result ───────────────────────────────────
result <- list(
  ticker       = ticker,
  current_price= current_price,
  signal       = list(
    action     = action,
    score      = round(final_score, 4),
    confidence = round(confidence, 4),
    rsi        = round(current_rsi, 2),
    macd_hist  = round(current_macd, 6),
    regime     = regime,
    risk_level = risk_level,
    stop_loss  = stop_loss,
    take_profit= take_profit
  ),
  forecast     = list(
    horizon_days   = n_days,
    point_estimate = tail(forecast_mean, 1),
    ci_80_low      = tail(forecast_lo80, 1),
    ci_80_high     = tail(forecast_hi80, 1),
    ci_95_low      = tail(forecast_lo95, 1),
    ci_95_high     = tail(forecast_hi95, 1)
  ),
  model        = "ORACLE_R_v2_ARIMA_RSI_MACD_EMA",
  timestamp    = as.character(Sys.time())
)

cat("\n--- JSON OUTPUT ---\n")
cat(toJSON(result, auto_unbox = TRUE, pretty = TRUE))
cat("\n\n=======================================================\n")
cat(sprintf("  Action : %s | Confidence: %.1f%% | Risk: %s\n",
            action, confidence * 100, risk_level))
cat(sprintf("  Entry  : ₹%.2f | SL: ₹%.2f | TP: ₹%.2f\n",
            current_price, stop_loss, take_profit))
cat("  ⚠️  Model signal — not financial advice. Use stop-losses.\n")
cat("=======================================================\n")
