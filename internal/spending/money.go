package spending

import (
	"fmt"
	"math"
	"math/big"
	"strings"
)

// MicroCents is an exact monetary amount in units of 1e-8 USD (one
// millionth of a cent). int64 gives headroom to ~92 billion USD — integer
// arithmetic only, so accumulation never drifts the way float64 does.
type MicroCents int64

// microCentsPerUSD is the fixed decimal scale: 1 USD = 1e8 micro-cents.
const microCentsPerUSD = 100_000_000

// maxUSDFracDigits is the finest granularity a manifest amount may declare.
const maxUSDFracDigits = 8

// ParseUSD converts a manifest USD string ("0.50", "5", "0.000003") to
// MicroCents exactly. Amounts must be non-negative, purely decimal, and
// have at most 8 fractional digits — anything finer is an error, never a
// silent rounding.
func ParseUSD(s string) (MicroCents, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty amount")
	}
	if s[0] == '+' || s[0] == '-' {
		return 0, fmt.Errorf("amount %q must be a plain non-negative decimal", s)
	}

	whole, frac, _ := strings.Cut(s, ".")
	if whole == "" && frac == "" {
		return 0, fmt.Errorf("invalid amount %q", s)
	}
	if whole == "" {
		whole = "0"
	}
	if len(frac) > maxUSDFracDigits {
		return 0, fmt.Errorf("amount %q has more than %d decimal places — finer than 1e-8 USD cannot be represented exactly", s, maxUSDFracDigits)
	}

	var total MicroCents
	for _, r := range whole {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("invalid amount %q", s)
		}
		d := MicroCents(r - '0')
		if total > (math.MaxInt64-d*microCentsPerUSD)/10 {
			return 0, fmt.Errorf("amount %q is too large", s)
		}
		total = total*10 + d*microCentsPerUSD
	}

	scale := MicroCents(microCentsPerUSD / 10)
	for _, r := range frac {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("invalid amount %q", s)
		}
		total += MicroCents(r-'0') * scale
		scale /= 10
	}
	return total, nil
}

// USD renders the amount as a plain decimal USD string with trailing zeros
// trimmed (but always at least two decimal places), e.g. 150000000 → "1.50".
func (m MicroCents) USD() string {
	neg := ""
	v := int64(m)
	if v < 0 {
		neg, v = "-", -v
	}
	whole := v / microCentsPerUSD
	frac := v % microCentsPerUSD
	s := fmt.Sprintf("%d.%08d", whole, frac)
	dot := strings.IndexByte(s, '.')
	for len(s) > dot+3 && s[len(s)-1] == '0' {
		s = s[:len(s)-1]
	}
	return neg + s
}

// Cost computes usage × pricePerUnit exactly and rounds UP to the next
// micro-cent — enforcement must never undercount. usage is the raw decimal
// string of a JSON number (json.Number.String()); it must be finite and
// non-negative.
func Cost(usage string, pricePerUnit MicroCents) (MicroCents, error) {
	u, ok := new(big.Rat).SetString(usage)
	if !ok {
		return 0, fmt.Errorf("usage value %q is not a decimal number", usage)
	}
	if u.Sign() < 0 {
		return 0, fmt.Errorf("usage value %q is negative", usage)
	}
	if pricePerUnit < 0 {
		return 0, fmt.Errorf("negative price %d", pricePerUnit)
	}

	u.Mul(u, new(big.Rat).SetInt64(int64(pricePerUnit)))

	// Ceiling division of the exact rational num/denom.
	num, denom := u.Num(), u.Denom()
	q, r := new(big.Int).QuoRem(num, denom, new(big.Int))
	if r.Sign() != 0 {
		q.Add(q, big.NewInt(1))
	}
	if !q.IsInt64() {
		return 0, fmt.Errorf("cost of usage %q at price %d µ¢/unit overflows", usage, pricePerUnit)
	}
	return MicroCents(q.Int64()), nil
}

// Add sums two amounts, failing closed on overflow instead of wrapping.
func Add(a, b MicroCents) (MicroCents, error) {
	if b > 0 && a > math.MaxInt64-b {
		return 0, fmt.Errorf("spending total overflows")
	}
	if b < 0 && a < math.MinInt64-b {
		return 0, fmt.Errorf("spending total underflows")
	}
	return a + b, nil
}
