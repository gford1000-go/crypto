package crypto

import (
	"errors"
	"reflect"
	"testing"
)

func TestEncrypt(t *testing.T) {
	type args struct {
		context      []byte
		plaintext    []byte
		keyCreator   KeyCreator
		nonceCreator NonceCreator
	}

	tests := []struct {
		name    string
		args    args
		want    *EncryptedData
		wantErr bool
	}{
		{name: "Nil data", args: args{plaintext: nil, keyCreator: nil, nonceCreator: CreateRandom}, want: nil, wantErr: true},
		{name: "Empty data", args: args{plaintext: []byte(""), keyCreator: nil, nonceCreator: CreateRandom}, want: nil, wantErr: true},
		{name: "Nil KeyCreator", args: args{plaintext: []byte("a"), keyCreator: nil, nonceCreator: CreateRandom}, want: nil, wantErr: true},
		{name: "Nil NonceCreator", args: args{
			plaintext:    []byte("a"),
			keyCreator:   func([]byte) (*KeyDetails, error) { return nil, errors.New("Boom") },
			nonceCreator: nil},
			want: nil, wantErr: true},
		{name: "Error from KeyCreator", args: args{
			plaintext:    []byte("a"),
			keyCreator:   func([]byte) (*KeyDetails, error) { return nil, errors.New("Boom") },
			nonceCreator: CreateRandom},
			want: nil, wantErr: true},
		{name: "Error from NonceCreator", args: args{
			plaintext: []byte("a"),
			keyCreator: func([]byte) (*KeyDetails, error) {
				return &KeyDetails{EncDetails: EncryptedKeyDetails{}, Key: [32]byte{}}, nil
			},
			nonceCreator: func(size int) ([]byte, error) { return nil, errors.New("Boom") }},
			want: nil, wantErr: true},
		{name: "Empty KeyDetails from KeyCreator and static Nonce", args: args{
			plaintext: []byte("a"),
			keyCreator: func([]byte) (*KeyDetails, error) {
				return &KeyDetails{EncDetails: EncryptedKeyDetails{}, Key: [32]byte{}}, nil
			},
			nonceCreator: func(size int) ([]byte, error) { return make([]byte, size), nil }},
			want:    &EncryptedData{KeyID: KeyID{}, Data: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 175, 82, 236, 111, 97, 213, 241, 52, 198, 28, 6, 73, 6, 133, 228, 88, 75}},
			wantErr: false},
		{name: "Non-empty KeyDetails (1) from KeyCreator and static Nonce", args: args{
			plaintext: []byte("a"),
			keyCreator: func([]byte) (*KeyDetails, error) {
				return &KeyDetails{
						EncDetails: EncryptedKeyDetails{
							KeyID:  KeyID{},
							EncKey: []byte("abcde")},
						Key: Key{}},
					nil
			},
			nonceCreator: func(size int) ([]byte, error) { return make([]byte, size), nil }},
			want:    &EncryptedData{KeyID: KeyID{}, Data: []byte{5, 0, 0, 0, 97, 98, 99, 100, 101, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 175, 82, 236, 111, 97, 213, 241, 52, 198, 28, 6, 73, 6, 133, 228, 88, 75}},
			wantErr: false},
		{name: "Non-empty KeyDetails (2) from KeyCreator and static Nonce", args: args{
			plaintext: []byte("a"),
			keyCreator: func([]byte) (*KeyDetails, error) {
				return &KeyDetails{
						EncDetails: EncryptedKeyDetails{
							KeyID:  KeyID{48, 87, 88, 5, 7},
							EncKey: []byte{3, 98, 99, 12, 251}},
						Key: Key{}},
					nil
			},
			nonceCreator: func(size int) ([]byte, error) { return make([]byte, size), nil }},
			want:    &EncryptedData{KeyID: [KeyIDSize]byte{48, 87, 88, 5, 7}, Data: []byte{5, 0, 0, 0, 3, 98, 99, 12, 251, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 175, 82, 236, 111, 97, 213, 241, 52, 198, 28, 6, 73, 6, 133, 228, 88, 75}},
			wantErr: false},
		{name: "Non-empty KeyDetails (3) from KeyCreator and static Nonce", args: args{
			plaintext: []byte("a"),
			keyCreator: func([]byte) (*KeyDetails, error) {
				return &KeyDetails{
						EncDetails: EncryptedKeyDetails{
							KeyID:  KeyID{48, 87, 88, 5, 7},
							EncKey: []byte{3, 98, 99, 12, 251}},
						Key: Key{62, 224, 227, 0, 167, 206, 72, 238, 8, 70, 116, 119, 95, 10, 36, 197, 95, 87, 224, 147, 181, 181, 227, 254, 215, 126, 23, 42, 120, 9, 203, 208}},
					nil
			},
			nonceCreator: func(size int) ([]byte, error) { return make([]byte, size), nil }},
			want:    &EncryptedData{KeyID: [KeyIDSize]byte{48, 87, 88, 5, 7}, Data: []byte{5, 0, 0, 0, 3, 98, 99, 12, 251, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 209, 76, 56, 161, 200, 237, 114, 195, 115, 184, 72, 23, 152, 170, 145, 237}},
			wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Encrypt(tt.args.context, tt.args.plaintext, tt.args.keyCreator, tt.args.nonceCreator)
			if (err != nil) != tt.wantErr {
				t.Errorf("Encrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Encrypt() = %v, want %v", got, tt.want)
			}
		})
	}
}
