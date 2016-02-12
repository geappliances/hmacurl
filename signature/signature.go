package signature

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// ComputeHmac256 signs a message with a secret
func ComputeHmac256(secret []byte, message string) []byte {
	key := []byte(secret)
	h := hmac.New(sha256.New, key)
	h.Write([]byte(message))
	return h.Sum(nil)
}

func calculateSigningKey(requestTime time.Time, region, service, secret string) []byte {
	_date := ComputeHmac256([]byte("AWS4"+secret), requestTime.Format("20060102"))
	_region := ComputeHmac256(_date, region)
	_service := ComputeHmac256(_region, service)
	return ComputeHmac256(_service, "aws4_request")
}

// CalculateSignature generates the HMAC signature string
func CalculateSignature(requestTime time.Time, message, region, service, secret string) string {
	return hex.EncodeToString(ComputeHmac256(calculateSigningKey(requestTime, region, service, secret), message))
}
