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
	"encoding/json"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type JWKRetriever interface {
	Retrieve(resolver JWKSURLResolver) (jwt.VerificationKeySet, error)
}

type JWKRetrieverWeb struct{}

func NewJWKRetrieverWeb() *JWKRetrieverWeb {
	return &JWKRetrieverWeb{}
}

func (r *JWKRetrieverWeb) Retrieve(resolver JWKSURLResolver) (jwt.VerificationKeySet, error) {
	url, e := resolver.Resolve()
	if e != nil {
		return jwt.VerificationKeySet{}, e
	}

	resp, e := http.Get(url)
	if e != nil {
		return jwt.VerificationKeySet{}, e
	}

	dec := json.NewDecoder(resp.Body)
	val := new(JsonWebKeySet)
	if e := dec.Decode(&val); e != nil {
		return jwt.VerificationKeySet{}, e
	}

	return val.ToVerificationKeySet()
}

type JWKRetrieverWebCaching struct {
	cached    *jwt.VerificationKeySet
	retrieved time.Time
	interval  time.Duration
	internal  *JWKRetrieverWeb
}

func NewJWKRetrieverWebCaching(interval time.Duration) *JWKRetrieverWebCaching {
	return &JWKRetrieverWebCaching{
		cached:    nil,
		retrieved: time.Unix(0, 0),
		interval:  interval,
		internal:  NewJWKRetrieverWeb(),
	}
}

func (r *JWKRetrieverWebCaching) Retrieve(resolver JWKSURLResolver) (jwt.VerificationKeySet, error) {
	// If we have not initialized the cache, or if our cached credentials are expired, renew them.
	if r.cached == nil || r.retrieved == time.Unix(0, 0) || r.retrieved.Add(r.interval).After(time.Now()) {
		k, e := r.internal.Retrieve(resolver)
		if e != nil {
			return jwt.VerificationKeySet{}, e
		} else {
			r.cached = &k
			r.retrieved = time.Now()
			return k, nil
		}
		// otherwise return cache
	} else {
		return *r.cached, nil
	}
}

type JWKRetrieverInternal struct {
	Set *JsonWebKeySet
}

func NewJWKRetrieverInternal(set *JsonWebKeySet) *JWKRetrieverInternal {
	return &JWKRetrieverInternal{
		Set: set,
	}
}

func (r *JWKRetrieverInternal) Retrieve(_ JWKSURLResolver) (*JsonWebKeySet, error) {
	return r.Set, nil
}
