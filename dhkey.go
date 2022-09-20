/*
 * Copyright 2012 Nan Deng
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package dhkx

import (
	"math/big"
)

type DHKey struct {
	X *big.Int
	Y *big.Int

	Group *DHGroup
}

func (h *DHKey) MarshalPublicKey() []byte {
	if h.Y == nil {
		return nil
	}
	if h.Group != nil {
		// len = ceil(bitLen(y) / 8)
		blen := (h.Group.p.BitLen() + 7) / 8
		ret := make([]byte, blen)
		copyWithLeftPad(ret, h.Y.Bytes())
		return ret
	}
	return h.Y.Bytes()
}

func (h *DHKey) MarshalPublicKeyString() string {
	if h.Y == nil {
		return ""
	}
	return h.Y.String()
}

func (h *DHKey) IsPrivateKey() bool {
	return h.X != nil
}

func NewPublicKey(s []byte) *DHKey {
	key := new(DHKey)
	key.Y = new(big.Int).SetBytes(s)
	return key
}

// copyWithLeftPad copies src to the end of dest, padding with zero bytes as
// needed.
func copyWithLeftPad(dest, src []byte) {
	numPaddingBytes := len(dest) - len(src)
	for i := 0; i < numPaddingBytes; i++ {
		dest[i] = 0
	}
	copy(dest[numPaddingBytes:], src)
}
