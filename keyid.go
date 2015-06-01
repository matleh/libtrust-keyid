package main

import (
    "bytes"
    "strings"
    "encoding/base32"
    "fmt"
    "os"
    "io/ioutil"
    "crypto"
    "crypto/x509"
    "encoding/pem"
)

// copied from docker/libtrust
func keyIDEncode(b []byte) string {
	s := strings.TrimRight(base32.StdEncoding.EncodeToString(b), "=")
	var buf bytes.Buffer
	var i int
	for i = 0; i < len(s)/4-1; i++ {
		start := i * 4
		end := start + 4
		buf.WriteString(s[start:end] + ":")
	}
	buf.WriteString(s[i*4:])
	return buf.String()
}

// copied from docker/libtrust
func keyIDFromCryptoKey(pubKey crypto.PublicKey) string {
	// Generate and return a 'libtrust' fingerprint of the public key.
	// For an RSA key this should be:
	//   SHA256(DER encoded ASN1)
	// Then truncated to 240 bits and encoded into 12 base32 groups like so:
	//   ABCD:EFGH:IJKL:MNOP:QRST:UVWX:YZ23:4567:ABCD:EFGH:IJKL:MNOP
	derBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return ""
	}
	hasher := crypto.SHA256.New()
	hasher.Write(derBytes)
        h := hasher.Sum(nil)[:30]
	return keyIDEncode(h)
}


func main() {
    if len(os.Args) < 2 {
        panic("no filename given")
    }
    filename := os.Args[1]
    fp, err := os.Open(filename)
    if err != nil {
        msg := fmt.Sprint("Can not open ", filename)
        panic(msg)
    }
    rawData, err := ioutil.ReadAll(fp)
    if err != nil {
        panic("Can not read data")
    }
    pemBlock, rawData := pem.Decode(rawData)
    cert, err := x509.ParseCertificate(pemBlock.Bytes)
    if err != nil {
        panic("Can not parse certificate")
    }
    key := crypto.PublicKey(cert.PublicKey)
    fmt.Println(keyIDFromCryptoKey(key))
}
