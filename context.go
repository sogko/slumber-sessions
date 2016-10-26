package sessions

import (
	. "github.com/grsouza/slumber-sessions/domain"

	"github.com/grsouza/slumber/domain"
	"net/http"
)

const TokenAuthorityKey domain.ContextKey = "slumber-mddlwr-session-token-authority-key"
const TokenClaimsKey domain.ContextKey = "slumber-mddlwr-session-token-claims-key"

func GetTokenAuthorityCtx(ctx domain.IContext, r *http.Request) ITokenAuthority {
	if ta := ctx.Get(r, TokenAuthorityKey); ta != nil {
		return ta.(ITokenAuthority)
	}
	return nil
}

func GetAuthenticatedClaimsCtx(ctx domain.IContext, r *http.Request) ITokenClaims {
	if claim := ctx.Get(r, TokenClaimsKey); claim != nil {
		return claim.(ITokenClaims)
	}
	return nil
}
