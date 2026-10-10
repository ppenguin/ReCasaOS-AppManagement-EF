package route

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/IceWhaleTech/CasaOS-AppManagement/pkg/config"
	"github.com/IceWhaleTech/CasaOS-AppManagement/pkg/gatewayclient"
	"github.com/labstack/echo/v4"
)

func TestSkipJWTNeedsServiceCredentialFromLoopback(t *testing.T) {
	const token = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	runtimePath := t.TempDir()
	if err := os.WriteFile(filepath.Join(runtimePath, gatewayclient.ServiceTokenFilename), []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := config.CommonInfo.RuntimePath
	config.CommonInfo.RuntimePath = runtimePath
	t.Cleanup(func() { config.CommonInfo.RuntimePath = previous })

	e := echo.New()
	skips := func(remote, authorization string) bool {
		req := httptest.NewRequest(http.MethodGet, "/v2/app_management/compose", nil)
		req.RemoteAddr = remote
		if authorization != "" {
			req.Header.Set(echo.HeaderAuthorization, authorization)
		}
		return skipJWT(e.NewContext(req, httptest.NewRecorder()))
	}

	for _, tc := range []struct {
		name, remote, authorization string
		want                        bool
	}{
		{"loopback without a credential", "127.0.0.1:40000", "", false},
		{"IPv6 loopback without a credential", "[::1]:40000", "", false},
		{"loopback with a user token", "127.0.0.1:40000", "Bearer some.user.jwt", false},
		{"loopback with a wrong credential", "127.0.0.1:40000", "Bearer " + token[:len(token)-1] + "0", false},
		{"the credential from the LAN", "192.0.2.10:40000", "Bearer " + token, false},
		{"loopback with the credential", "127.0.0.1:40000", "Bearer " + token, true},
		{"IPv6 loopback with the bare credential", "[::1]:40000", token, true},
	} {
		if got := skips(tc.remote, tc.authorization); got != tc.want {
			t.Errorf("%s: skipJWT = %v, want %v", tc.name, got, tc.want)
		}
	}
}
