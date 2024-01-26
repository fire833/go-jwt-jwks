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
	"bytes"
	"encoding/json"
	"testing"
)

func TestJWKURLFromOIDCProvider_Resolve(t *testing.T) {
	tests := []struct {
		name        string
		ProviderURL string
		want        string
		wantErr     bool
	}{
		{
			name:        "google",
			ProviderURL: "https://accounts.google.com/",
			want:        "https://www.googleapis.com/oauth2/v3/certs",
			wantErr:     false,
		},
		{
			name:        "microsoft",
			ProviderURL: "https://login.microsoftonline.com/common/v2.0",
			want:        "https://login.microsoftonline.com/common/discovery/v2.0/keys",
			wantErr:     false,
		},
		{
			name:        "linkedin",
			ProviderURL: "https://www.linkedin.com/oauth",
			want:        "https://www.linkedin.com/oauth/openid/jwks",
			wantErr:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conf := &JWKURLFromOIDCProvider{
				ProviderURL: tt.ProviderURL,
			}
			got, err := conf.Resolve()
			if (err != nil) != tt.wantErr {
				t.Errorf("JWKURLFromOIDCProvider.Resolve() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("JWKURLFromOIDCProvider.Resolve() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestJSONDecode(t *testing.T) {
	dec := json.NewDecoder(bytes.NewBufferString(`{"token_endpoint":"https://login.microsoftonline.com/common/oauth2/v2.0/token","token_endpoint_auth_methods_supported":["client_secret_post","private_key_jwt","client_secret_basic"],"jwks_uri":"https://login.microsoftonline.com/common/discovery/v2.0/keys","response_modes_supported":["query","fragment","form_post"],"subject_types_supported":["pairwise"],"id_token_signing_alg_values_supported":["RS256"],"response_types_supported":["code","id_token","code id_token","id_token token"],"scopes_supported":["openid","profile","email","offline_access"],"issuer":"https://login.microsoftonline.com/{tenantid}/v2.0","request_uri_parameter_supported":false,"userinfo_endpoint":"https://graph.microsoft.com/oidc/userinfo","authorization_endpoint":"https://login.microsoftonline.com/common/oauth2/v2.0/authorize","device_authorization_endpoint":"https://login.microsoftonline.com/common/oauth2/v2.0/devicecode","http_logout_supported":true,"frontchannel_logout_supported":true,"end_session_endpoint":"https://login.microsoftonline.com/common/oauth2/v2.0/logout","claims_supported":["sub","iss","cloud_instance_name","cloud_instance_host_name","cloud_graph_host_name","msgraph_host","aud","exp","iat","auth_time","acr","nonce","preferred_username","name","tid","ver","at_hash","c_hash","email"],"kerberos_endpoint":"https://login.microsoftonline.com/common/kerberos","tenant_region_scope":null,"cloud_instance_name":"microsoftonline.com","cloud_graph_host_name":"graph.windows.net","msgraph_host":"graph.microsoft.com","rbac_url":"https://pas.windows.net"}`))

	val := make(map[string]interface{})

	if e := dec.Decode(&val); e != nil {
		t.Log(e)
		t.Fail()
	}
}
