package auth_client

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	b64 "encoding/base64"
	"fmt"
	"net"

	"golang.org/x/crypto/pbkdf2"
)

func getFreeLocalPort() (int, error) {
	port := 49215
	foundOpenPort := false
	for port < 65535 {

		host := fmt.Sprintf("localhost:%d", port)
		Log.Infof("Trying %s", host)
		ln, err := net.Listen("tcp", host)
		if err != nil {
			Log.Debugf("Can't listen on port %d: %s", port, err)
			// move to next port
			port = port + 1
			continue
		}
		_ = ln.Close()
		foundOpenPort = true
		break
	}
	if foundOpenPort == false {
		return 0, NoFreePort
	}
	return port, nil
}
func GetAES256Key(password string) []byte{
    salt := make([]byte, 0, 8)
    if password == "" {
        Log.Error("password is empty")
        return nil
    }
 
    return pbkdf2.Key([]byte(password), salt, 4096, 32, sha1.New)
}
func Encrypt(plaintext string, encKey string) string {
    aes, err := aes.NewCipher([]byte(encKey))
    if err != nil {
        return ""
    }

    gcm, err := cipher.NewGCM(aes)
    if err != nil {
        return ""
    }

    // We need a 12-byte nonce for GCM (modifiable if you use cipher.NewGCMWithNonceSize())
    // A nonce should always be randomly generated for every encryption.
    nonce := make([]byte, gcm.NonceSize())
    _, err = rand.Read(nonce)
    if err != nil {
        return ""
    }

    // ciphertext here is actually nonce+ciphertext
    // So that when we decrypt, just knowing the nonce size
    // is enough to separate it from the ciphertext.
    ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
    
    //return string(ciphertext)
	return b64.StdEncoding.EncodeToString(ciphertext)
}

func Decrypt(ciphertext string, encKey string) string {
	ciphertextbytes, err := b64.StdEncoding.DecodeString(ciphertext)
	if err != nil{
		return ""
	}
	ciphertext = string(ciphertextbytes)
    aes, err := aes.NewCipher([]byte(encKey))
    if err != nil {
        return ""
    }

    gcm, err := cipher.NewGCM(aes)
    if err != nil {
        return ""
    }

    // Since we know the ciphertext is actually nonce+ciphertext
    // And len(nonce) == NonceSize(). We can separate the two.
    nonceSize := gcm.NonceSize()
    nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

    plaintext, err := gcm.Open(nil, []byte(nonce), []byte(ciphertext), nil)
    if err != nil {
        return ""
    }

    return string(plaintext)
}