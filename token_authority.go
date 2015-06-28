package sessions

import (
	. "github.com/sogko/slumber-sessions/domain"

	"fmt"
	"github.com/dgrijalva/jwt-go"
	"gopkg.in/mgo.v2/bson"
	"time"
)

func generateJTI() string {
	// We will use mongodb's object id as JTI
	// we then will use this id to blacklist tokens,
	// along with `exp` and `iat` claims.
	// As far as collisions go, ObjectId is guaranteed unique
	// within a collection; and this case our collection is `sessions`
	return bson.NewObjectId().Hex()
}

// TokenAuthority implements ITokenAuthority
type TokenAuthority struct {
	Options *TokenAuthorityOptions
}

type TokenAuthorityOptions struct {
	PrivateSigningKey []byte
	PublicSigningKey  []byte
}

func NewTokenAuthority(options *TokenAuthorityOptions) *TokenAuthority {
	ta := TokenAuthority{options}
	return &ta
}

func (ta *TokenAuthority) CreateNewSessionToken(claims ITokenClaims) (string, error) {

	c := claims.(*TokenClaims)

	token := jwt.New(jwt.SigningMethodRS512)

	token.Claims = map[string]interface{}{
		"userId": c.UserID,
		"exp":    time.Now().Add(time.Hour * 72).Format(time.RFC3339), // 3 days
		"iat":    time.Now().Format(time.RFC3339),
		"jti":    generateJTI(),
	}
	tokenString, err := token.SignedString(ta.Options.PrivateSigningKey)

	return tokenString, err
}

func (ta *TokenAuthority) VerifyTokenString(tokenString string) (IToken, ITokenClaims, error) {
	t, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return ta.Options.PublicSigningKey, nil
	})
	if err != nil {
		return nil, nil, err
	}

	var claims TokenClaims
	token := NewToken(t)
	if token.IsValid() {
		if token.Claims["userId"] != nil {
			claims.UserID = token.Claims["userId"].(string)
		}
		if token.Claims["jti"] != nil {
			claims.JTI = token.Claims["jti"].(string)
		}
		if token.Claims["iat"] != nil {
			claims.IssuedAt, _ = time.Parse(time.RFC3339, token.Claims["iat"].(string))
		}
		if token.Claims["exp"] != nil {
			claims.ExpireAt, _ = time.Parse(time.RFC3339, token.Claims["exp"].(string))
		}
	}

	return token, &claims, err
}
