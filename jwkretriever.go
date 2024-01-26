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
)

type JWKRetriever interface {
	Retrieve(resolver JWKSURLResolver) (*JsonWebKeySet, error)
}

type JWKRetrieverWeb struct{}

func NewJWKRetrieverWeb() *JWKRetrieverWeb {
	return &JWKRetrieverWeb{}
}

func (r *JWKRetrieverWeb) Retrieve(resolver JWKSURLResolver) (*JsonWebKeySet, error) {
	url, e := resolver.Resolve()
	if e != nil {
		return nil, e
	}

	resp, e := http.Get(url)
	if e != nil {
		return nil, e
	}

	dec := json.NewDecoder(resp.Body)
	val := new(JsonWebKeySet)
	if e := dec.Decode(&val); e != nil {
		return nil, e
	}

	return val, nil
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
