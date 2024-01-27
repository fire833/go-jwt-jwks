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
	"testing"
)

func TestJWKRetrieverWeb_Retrieve(t *testing.T) {
	tests := []struct {
		name     string
		resolver JWKSURLResolver
		wantErr  bool
	}{
		{
			name:     "testGoogle",
			resolver: NewJWKURLFromOIDCProvider("https://accounts.google.com/"),
			wantErr:  false,
		},
		{
			name:     "testMicrosoft",
			resolver: NewJWKURLFromOIDCProvider("https://login.microsoftonline.com/common/v2.0"),
			wantErr:  false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &JWKRetrieverWeb{}
			_, err := r.Retrieve(tt.resolver)
			if (err != nil) != tt.wantErr {
				t.Errorf("JWKRetrieverWeb.Retrieve() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
