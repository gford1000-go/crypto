package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
)

// Encrypt uses keyCreator to retrieve key details and then encrypts the plaintext
//   context provides metadata associated with the plaintext, and is used to map to a KeyID
//   plaintext is the data to be encrypted
//   keyCreator externalises the key generation process
//   nonceCreator externalises the nonce generation process - note that the nonce must be unique for each call
func Encrypt(context, plaintext []byte, keyCreator KeyCreator, nonceCreator NonceCreator) (*EncryptedData, error) {
	if plaintext == nil || len(plaintext) == 0 {
		return nil, errors.New("plaintext must not be nil or empty byte array")
	}

	if keyCreator == nil {
		return nil, errors.New("keyCreator must not be nil")
	}

	if nonceCreator == nil {
		return nil, errors.New("nonceCreator must not be nil")
	}

	var keyDetails, err = keyCreator(context)
	if err != nil {
		return nil, fmt.Errorf("Encrypt failed as keyCreator returned error: %s", err)
	}

	block, err := aes.NewCipher(keyDetails.Key[:])
	if err != nil {
		return nil, fmt.Errorf("Encrypt failed as aes.NewCipher returned error: %s", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("Encrypt failed as aes.NewGCM returned error: %s", err)
	}

	nonce, err := nonceCreator(gcm.NonceSize())
	if err != nil {
		return nil, fmt.Errorf("Encrypt failed as nonceCreator returned error: %s", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	// Create the prefix details for the ciphertext, to provide sufficient information for it to be decrypted later
	bs := make([]byte, encKeyByteArraySize)
	binary.LittleEndian.PutUint32(bs, uint32(len(keyDetails.EncDetails.EncKey)))
	return &EncryptedData{
			KeyID: keyDetails.EncDetails.KeyID,
			Data: bytes.Join([][]byte{
				bs,
				keyDetails.EncDetails.EncKey,
				ciphertext}, []byte(""))},
		nil
}
