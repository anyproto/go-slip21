package slip21

import (
	"encoding/hex"
	"reflect"
	"testing"
)

func hexMustDecode(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func TestDeriveForPath(t *testing.T) {
	// tests according to https://github.com/satoshilabs/slips/blob/master/slip-0021.md#example
	seed := hexMustDecode("c76c4ac4f4e4a00d6b274d5c39c700bb4a7ddc04fbc6f78e85ca75007b5b495f74a9043eeb77bdd53aa6fc3a0e31462270316fa04b8c19114c8798706cd02ac8")

	type args struct {
		path string
		seed []byte
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{
			name: "Key(m) – master node",
			args: args{
				path: "m",
				seed: seed,
			},
			want:    hexMustDecode("dbf12b44133eaab506a740f6565cc117228cbf1dd70635cfa8ddfdc9af734756"),
			wantErr: false,
		},
		{
			name: "Key(m/SLIP-0021)",
			args: args{
				path: "m/SLIP-0021",
				seed: seed,
			},
			want:    hexMustDecode("1d065e3ac1bbe5c7fad32cf2305f7d709dc070d672044a19e610c77cdf33de0d"),
			wantErr: false,
		},
		{
			name: "Key(m/SLIP-0021/Master encryption key)",
			args: args{
				path: "m/SLIP-0021/Master encryption key",
				seed: seed,
			},
			want:    hexMustDecode("ea163130e35bbafdf5ddee97a17b39cef2be4b4f390180d65b54cf05c6a82fde"),
			wantErr: false,
		},
		{
			name: "Key(m/SLIP-0021/Authentication key)",
			args: args{
				path: "m/SLIP-0021/Authentication key",
				seed: seed,
			},
			want:    hexMustDecode("47194e938ab24cc82bfa25f6486ed54bebe79c40ae2a5a32ea6db294d81861a6"),
			wantErr: false,
		},
		{
			name: "Key(invalid)",
			args: args{
				path: "invalid",
				seed: seed,
			},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DeriveForPath(tt.args.path, tt.args.seed)
			if (err != nil) != tt.wantErr {
				t.Errorf("DeriveForPath() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got.SymmetricKey(), tt.want) {
				t.Errorf("DeriveForPath() = %X, want %X", got.SymmetricKey(), tt.want)
			}
		})
	}
}

func TestNewMasterNode(t *testing.T) {
	seed := hexMustDecode("c76c4ac4f4e4a00d6b274d5c39c700bb4a7ddc04fbc6f78e85ca75007b5b495f74a9043eeb77bdd53aa6fc3a0e31462270316fa04b8c19114c8798706cd02ac8")

	type args struct {
		seed []byte
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{
			name:    "get a master key",
			args:    args{
				seed: seed,
			},
			want:    hexMustDecode("dbf12b44133eaab506a740f6565cc117228cbf1dd70635cfa8ddfdc9af734756"),
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewMasterNode(tt.args.seed)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewMasterNode() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got.SymmetricKey(), tt.want) {
				t.Errorf("NewMasterNode() = %v, want %v", got, tt.want)
			}
		})
	}
}
