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
	"crypto/rand"
	"errors"
	"io"
	"math/big"
)

type GroupID int

const (
	DHKX_ID1        GroupID = 1
	DHKX_ID2        GroupID = 2
	DHKX_ID14       GroupID = 14
	DHKX_ID15       GroupID = 15
	DHKX_IDZERO     GroupID = 0
	DHKX_ID_DEFAULT GroupID = 0
)

type DHGroup struct {
	p *big.Int
	g *big.Int
}

func (h *DHGroup) P() *big.Int {
	p := new(big.Int)
	p.Set(h.p)
	return p
}

func (h *DHGroup) G() *big.Int {
	g := new(big.Int)
	g.Set(h.g)
	return g
}

func (h *DHGroup) GeneratePrivateKey(randReader io.Reader) (key *DHKey, err error) {
	if randReader == nil {
		randReader = rand.Reader
	}

	// x should be in (0, p).
	// alternative approach:
	// x, err := big.Add(rand.Int(randReader, big.Sub(p, big.NewInt(1))), big.NewInt(1))
	//
	// However, since x is highly unlikely to be zero if p is big enough,
	// we would rather use an iterative approach below,
	// which is more efficient in terms of exptected running time.
	x, err := rand.Int(randReader, h.p)
	if err != nil {
		return
	}

	zero := big.NewInt(0)
	for x.Cmp(zero) == 0 {
		x, err = rand.Int(randReader, h.p)
		if err != nil {
			return
		}
	}
	key = new(DHKey)
	key.X = x

	// y = g ^ x mod p
	key.Y = new(big.Int).Exp(h.g, x, h.p)
	key.Group = h
	return
}

// This function fetches a DHGroup by its ID as defined in either RFC 2409 or
// RFC 3526.
//
// If you are unsure what to use use group ID 0 for a sensible default value
func GetGroup(groupID GroupID) (group *DHGroup, err error) {
	if groupID <= DHKX_IDZERO {
		groupID = DHKX_ID14
	}

	switch groupID {
	case DHKX_ID1:
		p, _ := new(big.Int).SetString("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF", 16)
		group = &DHGroup{
			g: new(big.Int).SetInt64(2),
			p: p,
		}
	case DHKX_ID2:
		p, _ := new(big.Int).SetString("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF", 16)
		group = &DHGroup{
			g: new(big.Int).SetInt64(2),
			p: p,
		}
	case DHKX_ID14:
		p, _ := new(big.Int).SetString("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)
		group = &DHGroup{
			g: new(big.Int).SetInt64(2),
			p: p,
		}
	case DHKX_ID15:
		p, _ := new(big.Int).SetString("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF", 16)
		group = &DHGroup{
			g: new(big.Int).SetInt64(2),
			p: p,
		}
	default:
		group = nil
		err = errors.New("DH: Unknown group")
	}
	return
}

// This function enables users to create their own custom DHGroup.
// Most users will not however want to use this function, and should prefer
// the use of GetGroup which supplies DHGroups defined in RFCs 2409 and 3526
//
// WARNING! You should only use this if you know what you are doing. The
// behavior of the group returned by this function is not defined if prime is
// not in fact prime.
func CreateGroup(prime, generator *big.Int) (group *DHGroup) {
	group = &DHGroup{
		g: generator,
		p: prime,
	}
	return
}

func (h *DHGroup) ComputeKey(pubkey *DHKey, privkey *DHKey) (key *DHKey, err error) {
	if h.p == nil {
		err = errors.New("DH: invalid group")
		return
	}
	if pubkey.Y == nil {
		err = errors.New("DH: invalid public key")
		return
	}
	if pubkey.Y.Sign() <= 0 || pubkey.Y.Cmp(h.p) >= 0 {
		err = errors.New("DH parameter out of bounds")
		return
	}
	if privkey.X == nil {
		err = errors.New("DH: invalid private key")
		return
	}
	k := new(big.Int).Exp(pubkey.Y, privkey.X, h.p)
	key = new(DHKey)
	key.Y = k
	key.Group = h
	return
}
