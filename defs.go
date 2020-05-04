package crypto

// KeyIDSize is the size of the keyID
const KeyIDSize = 16

// KeyID is an identifier used to identify encryption keys
type KeyID [KeyIDSize]byte

// KeySize is the size of the key
const KeySize = 32

// Key is the type of the encryption key
type Key [KeySize]byte

// InvalidKey signifies the key is not populated
var InvalidKey = Key{}

// encKeyByteArraySize is the size of the buffer defined to hold the length of the encrypted key
const encKeyByteArraySize = 4

// EncryptedKeyDetails provide the details needed to allow the key to be decrypted
type EncryptedKeyDetails struct {
	KeyID  KeyID  // An identifier associated with the key, facilitating decryption
	EncKey []byte // Encrypted key details
}

// KeyDetails provide the key in plaintext (for immediate encryption activity only), encrypted
// so this can be prepended to the ciphertext, and with an ID that supports decryption
type KeyDetails struct {
	EncDetails EncryptedKeyDetails // Details needed to decrypt the key in the future
	Key        Key                 // Plaintext of the key
}

// KeyCreator is a function that returns an instance of KeyDetails, with supplied bytes used to map to
// the KeyID contained within the KeyDetails
type KeyCreator func([]byte) (*KeyDetails, error)

// NonceCreator provides nonce values for the AES encryption - these should be unique for each encrypt operation
type NonceCreator func(int) ([]byte, error)

// EncryptedData is returned by Encrypt after sucessful encryption
type EncryptedData struct {
	KeyID KeyID  // An identifier associated with the key used to encrypt the data
	Data  []byte // The encrypted data
}

// KeyRetriever is a function that provides a key given an EncryptedKeyDetails instance
type KeyRetriever func(*EncryptedKeyDetails) (Key, error)
