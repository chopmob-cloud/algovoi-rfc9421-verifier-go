package verifier

import "math/big"

// WeakKeyError is returned when an Ed25519 public key is non-canonical,
// off-curve, or small-order. It is a fail-closed trust-boundary rejection made
// BEFORE any signature verification.
//
// Why this gate is needed: libsodium's basic verify and some ZIP215 verifiers
// accept small-order (and some non-canonical) public keys. For an audited offline
// verifier that treats the resolved key as the trust anchor, accepting such a key
// is a defect. This gate derives small-order-ness mathematically ([8]P == identity)
// via RFC 8032 Appendix A arithmetic rather than trusting a hard-coded blocklist.
type WeakKeyError struct{ msg string }

func (e *WeakKeyError) Error() string { return e.msg }

// Ed25519 field / curve constants (RFC 8032 Appendix A).
var (
	edP      = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19)) // 2^255 - 19
	edD      *big.Int
	edSqrtM1 *big.Int
	bigOne   = big.NewInt(1)
	bigTwo   = big.NewInt(2)
)

func init() {
	// d = -121665 * inverse(121666) mod p
	inv := new(big.Int).ModInverse(big.NewInt(121666), edP)
	edD = new(big.Int).Mul(big.NewInt(-121665), inv)
	edD.Mod(edD, edP)
	// sqrt(-1) = 2^((p-1)/4) mod p
	exp := new(big.Int).Div(new(big.Int).Sub(edP, bigOne), big.NewInt(4))
	edSqrtM1 = new(big.Int).Exp(bigTwo, exp, edP)
}

func modP(x *big.Int) *big.Int { return new(big.Int).Mod(x, edP) }

// edPoint is an extended homogeneous coordinate (X, Y, Z, T).
type edPoint struct{ X, Y, Z, T *big.Int }

// recoverX recovers the x-coordinate for the given y and sign bit, or nil if the
// encoding is non-canonical (y >= p) or the point is not on the curve.
func recoverX(y *big.Int, sign uint) *big.Int {
	if y.Cmp(edP) >= 0 {
		return nil // non-canonical y encoding
	}
	// x2 = (y*y - 1) * inv(d*y*y + 1) mod p
	yy := modP(new(big.Int).Mul(y, y))
	num := modP(new(big.Int).Sub(yy, bigOne))
	den := modP(new(big.Int).Add(modP(new(big.Int).Mul(edD, yy)), bigOne))
	denInv := new(big.Int).Exp(den, new(big.Int).Sub(edP, bigTwo), edP) // Fermat inverse
	x2 := modP(new(big.Int).Mul(num, denInv))

	if x2.Sign() == 0 {
		if sign == 1 {
			return nil
		}
		return big.NewInt(0)
	}

	// x = x2 ^ ((p+3)/8) mod p
	expX := new(big.Int).Div(new(big.Int).Add(edP, big.NewInt(3)), big.NewInt(8))
	x := new(big.Int).Exp(x2, expX, edP)

	// if x*x != x2, multiply by sqrt(-1)
	if modP(new(big.Int).Sub(modP(new(big.Int).Mul(x, x)), x2)).Sign() != 0 {
		x = modP(new(big.Int).Mul(x, edSqrtM1))
	}
	// if still not a square root, the point is not on the curve
	if modP(new(big.Int).Sub(modP(new(big.Int).Mul(x, x)), x2)).Sign() != 0 {
		return nil
	}

	if x.Bit(0) != sign {
		x = new(big.Int).Sub(edP, x)
	}
	return x
}

// decodePoint decodes a 32-byte Ed25519 public key to extended coords, or nil if
// the encoding is invalid (wrong length, non-canonical, or off-curve).
func decodePoint(pk []byte) *edPoint {
	if len(pk) != 32 {
		return nil
	}
	// Little-endian integer.
	le := make([]byte, 32)
	for i := 0; i < 32; i++ {
		le[i] = pk[31-i]
	}
	y := new(big.Int).SetBytes(le)
	sign := uint(y.Bit(255))
	// Clear the sign bit: y &= 2^255 - 1.
	mask := new(big.Int).Sub(new(big.Int).Lsh(bigOne, 255), bigOne)
	y.And(y, mask)

	x := recoverX(y, sign)
	if x == nil {
		return nil
	}
	return &edPoint{
		X: x,
		Y: y,
		Z: big.NewInt(1),
		T: modP(new(big.Int).Mul(x, y)),
	}
}

// edAdd adds two points in extended homogeneous coordinates (RFC 8032 App. A).
func edAdd(p, q *edPoint) *edPoint {
	a := modP(new(big.Int).Mul(new(big.Int).Sub(p.Y, p.X), new(big.Int).Sub(q.Y, q.X)))
	b := modP(new(big.Int).Mul(new(big.Int).Add(p.Y, p.X), new(big.Int).Add(q.Y, q.X)))
	c := modP(new(big.Int).Mul(new(big.Int).Mul(bigTwo, new(big.Int).Mul(p.T, q.T)), edD))
	d := modP(new(big.Int).Mul(bigTwo, new(big.Int).Mul(p.Z, q.Z)))
	e := new(big.Int).Sub(b, a)
	f := new(big.Int).Sub(d, c)
	g := new(big.Int).Add(d, c)
	h := new(big.Int).Add(b, a)
	return &edPoint{
		X: modP(new(big.Int).Mul(e, f)),
		Y: modP(new(big.Int).Mul(g, h)),
		Z: modP(new(big.Int).Mul(f, g)),
		T: modP(new(big.Int).Mul(e, h)),
	}
}

// mul8 computes [8]P.
func mul8(p *edPoint) *edPoint {
	p2 := edAdd(p, p)
	p4 := edAdd(p2, p2)
	return edAdd(p4, p4)
}

// isIdentity reports whether P is the identity element (affine (0, 1)).
func isIdentity(p *edPoint) bool {
	return modP(p.X).Sign() == 0 && modP(new(big.Int).Sub(p.Y, p.Z)).Sign() == 0
}

// IsSmallOrder reports whether pk decodes to a point whose order divides 8
// (including the identity). It returns false for keys that fail to decode.
func IsSmallOrder(pk []byte) bool {
	p := decodePoint(pk)
	if p == nil {
		return false
	}
	return isIdentity(mul8(p))
}

// CheckEd25519PublicKey returns a *WeakKeyError if pk is non-canonical,
// off-curve, or small-order. It returns nil for a canonical, on-curve,
// large-order public key.
func CheckEd25519PublicKey(pk []byte) error {
	p := decodePoint(pk)
	if p == nil {
		return &WeakKeyError{msg: "public key is not a canonical on-curve Ed25519 point"}
	}
	if isIdentity(mul8(p)) {
		return &WeakKeyError{msg: "public key is a small-order Ed25519 point"}
	}
	return nil
}
