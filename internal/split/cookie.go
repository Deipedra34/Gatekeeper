package split

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"strconv"
	"strings"
)

// CookieSigner signs and checks sticky cookies. A cookie holds the
// client's bucket, not its variant, so a client with a cookie moves with
// weight changes exactly like a hashed client does, and a rolled-back
// variant loses its cookie clients too. The signature stops a client
// from writing its own bucket to choose a variant.
type CookieSigner struct {
	secret []byte
}

// NewCookieSigner returns a signer using secret, or a random one when
// secret is nil (cookies then only verify in this process).
func NewCookieSigner(secret []byte) *CookieSigner {
	if secret == nil {
		secret = make([]byte, 32)
		_, _ = rand.Read(secret)
	}
	return &CookieSigner{secret: secret}
}

// sigLen is the signature's length in base64url characters (96 bits).
const sigLen = 16

func (s *CookieSigner) sig(salt string, bucket int) string {
	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(salt))
	mac.Write([]byte{0})
	mac.Write([]byte(strconv.Itoa(bucket)))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))[:sigLen]
}

// Sign returns the cookie value for bucket on the route salted salt.
func (s *CookieSigner) Sign(salt string, bucket int) string {
	return strconv.Itoa(bucket) + "." + s.sig(salt, bucket)
}

// Verify returns the bucket a cookie value holds, if it's well formed
// and was signed for salt with this signer's secret.
func (s *CookieSigner) Verify(salt, value string) (int, bool) {
	num, sig, ok := strings.Cut(value, ".")
	if !ok || len(sig) != sigLen || len(num) == 0 || len(num) > 5 {
		return 0, false
	}
	bucket, err := strconv.Atoi(num)
	if err != nil || bucket < 0 || bucket >= Buckets || strconv.Itoa(bucket) != num {
		return 0, false
	}
	if !hmac.Equal([]byte(sig), []byte(s.sig(salt, bucket))) {
		return 0, false
	}
	return bucket, true
}

// RandomBucket returns a uniformly random bucket, for a client seen for
// the first time with cookie stickiness.
func RandomBucket() int {
	var b [8]byte
	_, _ = rand.Read(b[:])
	var x uint64
	for _, c := range b {
		x = x<<8 | uint64(c)
	}
	return int(x % Buckets)
}
