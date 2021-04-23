package verkle

import (
	"errors"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rlp"
)

const ErrInvalidNodeEncoding = "invalid node encoding"

func ParseNode(serialized []byte, tc *TreeConfig) (VerkleNode, error) {
	elems, _, err := rlp.SplitList(serialized)
	if err != nil {
		return nil, err
	}
	c, err := rlp.CountValues(elems)
	if err != nil {
		return nil, err
	}

	if c == 1 {
		// hashedNode
		return parseHashedNode(elems)
	} else if c == 2 {
		// either leaf or internal
		kind, first, rest, err := rlp.Split(elems)
		if err != nil {
			return nil, err
		}
		if kind != rlp.String {
			return nil, errors.New(ErrInvalidNodeEncoding)
		}

		if len(first) == 32 {
			value, _, err := rlp.SplitString(rest)
			if err != nil {
				return nil, err
			}
			return &LeafNode{key: first, value: value}, nil
		} else if len(first) == 128 {
			// internal
			children, _, err := rlp.SplitList(rest)
			if err != nil {
				return nil, err
			}
			return createInternalNode(first, children, tc)
		} else {
			return nil, errors.New(ErrInvalidNodeEncoding)
		}
	} else {
		return nil, errors.New(ErrInvalidNodeEncoding)
	}
}

func createInternalNode(bitlist []byte, raw []byte, tc *TreeConfig) (*InternalNode, error) {
	// TODO: fix depth
	n := (newInternalNode(0, tc)).(*InternalNode)
	indices := indicesFromBitlist(bitlist)
	for _, index := range indices {
		el, rest, err := rlp.SplitList(raw)
		if err != nil {
			return nil, err
		}
		c, err := rlp.CountValues(el)
		if err != nil {
			return nil, err
		}
		switch c {
		case 1:
			// hashed node
			hashed, err := parseHashedNode(el)
			if err != nil {
				return nil, err
			}
			n.children[index] = hashed
		case 2:
			// leaf
			leaf, err := parseLeafNode(el)
			if err != nil {
				return nil, err
			}
			n.children[index] = leaf
		}
		raw = rest
	}
	return n, nil
}

func parseLeafNode(raw []byte) (*LeafNode, error) {
	key, rest, err := rlp.SplitString(raw)
	if err != nil {
		return nil, err
	}
	value, _, err := rlp.SplitString(rest)
	if err != nil {
		return nil, err
	}
	return &LeafNode{key, value}, nil
}

func parseHashedNode(raw []byte) (*HashedNode, error) {
	h, _, err := rlp.SplitString(raw)
	if err != nil {
		return nil, err
	}
	return &HashedNode{hash: common.BytesToHash(h)}, nil
}

func indicesFromBitlist(bitlist []byte) []int {
	indices := make([]int, 0)
	for i, b := range bitlist {
		if b&0xff == 0x00 {
			continue
		}
		for j := 0; j < 8; j++ {
			mask := byte(1 << j)
			if b&mask == mask {
				index := i*8 + j
				indices = append(indices, index)
			}
		}
	}
	return indices
}
