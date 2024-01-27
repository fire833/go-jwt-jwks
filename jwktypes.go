/*
*	Copyright (C) 2024 Kendall Tauser
*
*	This program is free software; you can redistribute it and/or modify
*	it under the terms of the GNU General Public License as published by
*	the Free Software Foundation; either version 2 of the License, or
*	(at your option) any later version.
*
*	This program is distributed in the hope that it will be useful,
*	but WITHOUT ANY WARRANTY; without even the implied warranty of
*	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*	GNU General Public License for more details.
*
*	You should have received a copy of the GNU General Public License along
*	with this program; if not, write to the Free Software Foundation, Inc.,
*	51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

package gojwtjwks

import (
	"crypto/rsa"
	"math/big"

	"github.com/golang-jwt/jwt/v5"
)

type JsonWebKeySet struct {
	// Set of keys within this key set.
	Keys []*JsonWebKey `json:"keys"`
}

func (s *JsonWebKeySet) ToVerificationKeySet() (jwt.VerificationKeySet, error) {
	vks := jwt.VerificationKeySet{}

	for _, jwk := range s.Keys {
		switch jwk.Kty {
		case "RSA":
			n, e := parsebase64TrimPadding(jwk.Modulus)
			if e != nil {
				return jwt.VerificationKeySet{}, e
			}

			exp, e := parsebase64TrimPadding(jwk.Exponent)
			if e != nil {
				return jwt.VerificationKeySet{}, e
			}

			vks.Keys = append(vks.Keys, rsa.PublicKey{
				E: int(new(big.Int).SetBytes(exp).Uint64()),
				N: new(big.Int).SetBytes(n),
			})
		}
	}

	return vks, nil
}

type JsonWebKey struct {
	// The specific cryptographic algorithm used with the key.
	Algorithm string `json:"alg,omitempty"`
	// The family of cryptographic algorithms used with the key.
	Kty string `json:"kty,omitempty"`
	// How the key was meant to be used; sig represents the signature.
	Use string `json:"use,omitempty"`

	// The modulus for the RSA public key. (N)
	Modulus string `json:"n,omitempty"`
	// The exponent for the RSA public key. (E)
	Exponent string `json:"e,omitempty"`
	// The unique identifier for the key.
	KeyID string `json:"kid,omitempty"`

	// The thumbprint of the x.509 cert (SHA-1 thumbprint).
	X509Signature string `json:"x5t,omitempty"`
	// The x.509 certificate chain. The first entry in the array is the certificate to use for token verification; the other certificates can be used to verify this first certificate.
	X509CertChain []string `json:"x5c,omitempty"`
}
