package slip21

import (
	"crypto/hmac"
	"crypto/sha512"
	"fmt"
	"regexp"
	"strings"
)

const (
	// you should use this Prefix for your path
	Prefix = "m/SLIP-0021"

	// As in https://github.com/satoshilabs/slips/blob/master/slip-0021.md
	seedModifier = "Symmetric key seed"
)

var (
	ErrInvalidPath = fmt.Errorf("invalid derivation path")
	pathRegex      = regexp.MustCompile("^m(/.+)*$")
)

type Node struct {
	chainCode []byte
	key       []byte
}

// DeriveForPath derives key for a path in slip-0021 format and a seed
func DeriveForPath(path string, seed []byte) (*Node, error) {
	if !IsValidPath(path) {
		return nil, ErrInvalidPath
	}

	key, err := NewMasterNode(seed)
	if err != nil {
		return nil, err
	}

	labels := strings.Split(path, "/")
	for _, label := range labels[1:] {
		key, err = key.Derive([]byte(label))
		if err != nil {
			return nil, err
		}
	}

	return key, nil
}

// NewMasterNode generates a new master key from seed
func NewMasterNode(seed []byte) (*Node, error) {
	hash := hmac.New(sha512.New, []byte(seedModifier))
	_, err := hash.Write(seed)
	if err != nil {
		return nil, err
	}
	sum := hash.Sum(nil)
	key := &Node{
		chainCode: sum[0:32],
		key:       sum[32:],
	}

	return key, nil
}

// Derive derives a child node with a label
func (k *Node) Derive(label []byte) (*Node, error) {
	hash := hmac.New(sha512.New, k.chainCode)
	_, err := hash.Write(append([]byte{0x0}, label...))
	if err != nil {
		return nil, err
	}
	sum := hash.Sum(nil)
	newKey := &Node{
		chainCode: sum[:32],
		key:       sum[32:],
	}
	return newKey, nil
}

// SymmetricKey returns 256 bit symmetric key for the current node
func (k *Node) SymmetricKey() []byte {
	if k == nil {
		return nil
	}

	return k.key
}

// IsValidPath check whether or not the path has valid segments
func IsValidPath(path string) bool {
	return pathRegex.MatchString(path)
}
