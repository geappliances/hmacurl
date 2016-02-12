package utilities

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// DataToSha256Encoded returns a SHA-256 encoded version of a byte array
func DataToSha256Encoded(data []byte) string {
	sha := sha256.Sum256(data)
	return hex.EncodeToString(sha[:])
}

// GenerateSignedHeader creates the AWS credential string
func GenerateSignedHeader(accessKey, signature, region, service, date, signedHeaders string) string {
	return fmt.Sprintf("%s Credential=%s/%s/%s/%s/%s, SignedHeaders=%s, Signature=%s", "AWS4-HMAC-SHA256", accessKey, date, region, service, "aws4_request", signedHeaders, signature)
}
