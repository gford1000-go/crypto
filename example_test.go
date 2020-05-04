package crypto

import (
	"crypto/sha256"
	"errors"
	"fmt"
)

// MyKeyManager is a simple in-memory key store
type MyKeyManager struct {
	keys map[KeyID]map[[32]byte]Key // The map of keys
}

// saveKey stores the Key as a double map
func (k *MyKeyManager) saveKey(keyID KeyID, key Key, encryptedKey [32]byte) {
	if k.keys == nil {
		k.keys = make(map[KeyID]map[[32]byte]Key)
	}
	_, ok := k.keys[keyID]
	if !ok {
		k.keys[keyID] = make(map[[32]byte]Key)
	}
	k.keys[keyID][encryptedKey] = key
}

// createKeyID can be used to map the context into distinct buckets of keys
func (k *MyKeyManager) createKeyID(context []byte) KeyID {
	return KeyID{} // Here just add to "global" KeyID space
}

// createKey creates a fixed size Key from a random slice of bytes
func (k *MyKeyManager) createKey() Key {
	keyBytes, _ := CreateRandom(KeySize)
	var key Key
	copy(key[:], keyBytes)
	return key
}

// createEncryptedKey can be used to encrypt the supplied key with an envelope key
func (k *MyKeyManager) createEncryptedKey(key Key) [32]byte {
	return sha256.Sum256(key[:]) // Here just hash the key
}

// Create constructs a suitable key based on the context
func (k *MyKeyManager) Create(context []byte) (*KeyDetails, error) {
	keyID := k.createKeyID(context)
	key := k.createKey()
	encKey := k.createEncryptedKey(key)

	k.saveKey(keyID, key, encKey)

	keyDetails := &KeyDetails{
		Key: key,
		EncDetails: EncryptedKeyDetails{
			KeyID:  keyID,
			EncKey: encKey[:],
		},
	}
	return keyDetails, nil
}

// Get uses the specified details to attempt to return the Key
func (k *MyKeyManager) Get(details *EncryptedKeyDetails) (Key, error) {
	if k.keys == nil {
		k.keys = make(map[KeyID]map[[32]byte]Key)
	}
	if m, ok := k.keys[details.KeyID]; ok {
		var encryptedKey [32]byte
		copy(encryptedKey[:], details.EncKey)
		if key, ok := m[encryptedKey]; ok {
			return key, nil
		}
	}
	return InvalidKey, errors.New("Invalid key")
}

func Example() {
	// Create a key manager
	manager := &MyKeyManager{}

	// Encrypt some data, with a particular context
	encryptedData, _ := Encrypt([]byte("My Context"), []byte("Hello World"), manager.Create, CreateRandom)

	// Decrypt back to bytes, based only on the encrypted data
	decryptedData, _ := Decrypt(encryptedData, manager.Get)

	fmt.Printf("%s\n", decryptedData)
	// Output: Hello World
}
