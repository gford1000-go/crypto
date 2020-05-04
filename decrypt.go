package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
)

// Decrypt calls the retriever to obtain a key to decrypt the data.
// data is expected to have the keyID in its first bytes, of length
// defined by GetDataKeyIDSize
func Decrypt(data *EncryptedData, retriever KeyRetriever) ([]byte, error) {

	if data == nil {
		return nil, errors.New("data must not be nil")
	}

	if data.Data == nil || len(data.Data) == 0 {
		return data.Data, nil
	}

	if len(data.Data) < encKeyByteArraySize {
		return nil, errors.New("Invalid data provided")
	}

	if retriever == nil {
		return nil, errors.New("retriever must not be nil")
	}

	var encKeySize = binary.LittleEndian.Uint32(data.Data[:encKeyByteArraySize])
	var encKey, ciphertextWithNonce = data.Data[encKeyByteArraySize : encKeyByteArraySize+encKeySize], data.Data[encKeyByteArraySize+encKeySize:]

	var key, err = retriever(&EncryptedKeyDetails{KeyID: data.KeyID, EncKey: encKey})
	if err != nil {
		return nil, fmt.Errorf("Decrypt failed as retreiver returned an error: %s", err)
	}

	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, fmt.Errorf("Decrypt failed as aes.NewCipher returned an error: %s", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("Decrypt failed as aes.NewGCM returned an error: %s", err)
	}

	var nonceSize = gcm.NonceSize()
	if len(ciphertextWithNonce) < nonceSize {
		return nil, errors.New("Invalid ciphertext provided")
	}

	var nonce, ciphertext = ciphertextWithNonce[:nonceSize], ciphertextWithNonce[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("Decrypt failed with error: %s", err)
	}

	return plaintext, nil
}
