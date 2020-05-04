package crypto

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"reflect"
	"testing"
)

func initTest(passphrase, context, plaintext string) (*EncryptedData, KeyRetriever, error) {
	var keyDetails KeyDetails
	keyCreator, retriever := func(details *KeyDetails) (KeyCreator, KeyRetriever) {
		var key = sha256.Sum256([]byte(passphrase))

		// KeyID defines the family from which the key is drawn
		var keyID [KeyIDSize]byte
		copy(keyID[:], key[:KeyIDSize])

		// Use reversing the bytes in the key as a proxy for encrypt/decrypt
		reverser := func(k []byte) *Key {
			var reversed = &Key{}
			for i := 0; i < len(k); i++ {
				(*reversed)[i] = k[len(k)-1-i]
			}
			return reversed
		}

		// Populate the instance with calculated values so that they remain during the encryption activity
		*details = KeyDetails{
			EncDetails: EncryptedKeyDetails{KeyID: keyID, EncKey: reverser(key[:])[:]},
			Key:        key,
		}

		// Creator and Retriever functions return the KeyDetails information we have just created
		return func([]byte) (*KeyDetails, error) { return details, nil },
			func(d *EncryptedKeyDetails) (Key, error) { return *reverser(d.EncKey), nil }
	}(&keyDetails)

	var encrypteData, err = Encrypt([]byte(context), []byte(plaintext), keyCreator, CreateRandom)
	if err != nil {
		return nil, nil, fmt.Errorf("Encrypt error: %s", err)
	}

	return encrypteData, retriever, nil
}

func Test_successful_decryption(t *testing.T) {

	var passphrase = "This is a passphrase of any length"
	var context = "Some metadata for the plaintext"
	var plaintext = "Hello World! Hello World! Hello World! Hello World! Hello World! Hello World! Hello World! "

	encryptedData, retriever, err := initTest(passphrase, context, plaintext)
	if err != nil {
		t.Error(err)
		return
	}

	retrievedPlaintext, err := Decrypt(encryptedData, retriever)
	if err != nil {
		t.Error(err.Error())
		return
	}

	if !bytes.Equal([]byte(plaintext), retrievedPlaintext) {
		t.Error("Mismatched plaintext")
	}
}

func Test_decrypt(t *testing.T) {
	type args struct {
		data      *EncryptedData
		retriever KeyRetriever
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{name: "Nil retriever", args: args{data: &EncryptedData{Data: []byte{0, 0, 0, 0}}, retriever: nil}, want: nil, wantErr: true},
		{name: "Nil data", args: args{data: nil, retriever: nil}, want: nil, wantErr: true},
		{name: "Empty data (1)", args: args{data: &EncryptedData{Data: nil}, retriever: nil}, want: nil, wantErr: false},
		{name: "Empty data (2)", args: args{data: &EncryptedData{Data: []byte("")}, retriever: nil}, want: []byte(""), wantErr: false},
		{name: "Error in retriever", args: args{
			data:      &EncryptedData{Data: []byte{0, 0, 0, 0}},
			retriever: func(*EncryptedKeyDetails) (Key, error) { return InvalidKey, errors.New("Boom") }},
			want: nil, wantErr: true},
		{name: "Short key returned by retriever", args: args{
			data:      &EncryptedData{Data: []byte{0, 0, 0, 0}},
			retriever: func(*EncryptedKeyDetails) (Key, error) { return Key{'a', 'b'}, nil }},
			want: nil, wantErr: true},
		{name: "Bad key returned by retriever", args: args{
			data: &EncryptedData{Data: []byte{0, 0, 0, 0, 0}},
			retriever: func(*EncryptedKeyDetails) (Key, error) {
				return Key{'a', 'b', 'c', 'd', 'e', '0', '1', '2', '3', '4', '5', '6', '7'}, nil
			}},
			want: nil, wantErr: true},
		{name: "Bad data - too short", args: args{
			data: &EncryptedData{Data: []byte{0, 0, 0}},
			retriever: func(*EncryptedKeyDetails) (Key, error) {
				return Key{'a', 'b', 'c', 'd', 'e', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9'}, nil
			}},
			want: nil, wantErr: true},
		{name: "Bad data - no nonce", args: args{
			data: &EncryptedData{Data: []byte{0, 0, 0, 0}},
			retriever: func(*EncryptedKeyDetails) (Key, error) {
				return Key{'a', 'b', 'c', 'd', 'e', 'f', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9'}, nil
			}},
			want: nil, wantErr: true},
		{name: "Invalid key returned by retriever", args: args{
			data: &EncryptedData{Data: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
			retriever: func(*EncryptedKeyDetails) (Key, error) {
				return Key{'a', 'b', 'c', 'd', 'e', 'f', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9'}, nil
			}},
			want: nil, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Decrypt(tt.args.data, tt.args.retriever)
			if (err != nil) != tt.wantErr {
				t.Errorf("Decrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Decrypt() = %v, want %v", got, tt.want)
			}
		})
	}
}
