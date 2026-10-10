package route

import (
	"github.com/IceWhaleTech/CasaOS-AppManagement/pkg/config"
	"github.com/IceWhaleTech/CasaOS-AppManagement/pkg/gatewayclient"
	"github.com/labstack/echo/v4"
)

// skipJWT: in-stack service = loopback + gateway service credential.
// loopback alone ≠ identity (local processes, host-network containers); API installs apps as root
func skipJWT(c echo.Context) bool {
	realIP := c.RealIP()
	return (realIP == "::1" || realIP == "127.0.0.1") &&
		gatewayclient.ServiceAuthorizationMatches(config.CommonInfo.RuntimePath, c.Request().Header.Get(echo.HeaderAuthorization))
}
