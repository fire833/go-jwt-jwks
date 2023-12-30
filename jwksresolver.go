/*
*	Copyright (C) 2023 Kendall Tauser
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
	"errors"
	"fmt"
	"net/http"
)

// JWKSURLResolver provides an interface for users to define how to resolve
type JWKSURLResolver interface {
	Resolve() (string, error)
}

type JWKURLString string

func (url JWKURLString) Resolve() string {
	return string(url)
}

type JWKURLFromOIDCProvider struct {
	ProviderURL string
}

func (conf *JWKURLFromOIDCProvider) Resolve() (string, error) {
	resp, e := http.Get(fmt.Sprintf("%s/.well-known/openid-configuration", conf.ProviderURL))
	if e != nil {
		return "", e
	}

	dec := json.NewDecoder(resp.Body)
	val := make(map[string]interface{})
	if e := dec.Decode(&val); e != nil {
		return "", e
	}

	if v, ok := val["jwks_uri"]; ok {
		return v.(string), nil
	} else {
		return "", errors.New("jwks URI not found with provider")
	}
}
