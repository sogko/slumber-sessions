package sessions

import (
	. "github.com/sogko/slumber-sessions/domain"

	"fmt"
	"time"

	"github.com/dgrijalva/jwt-go"
	"gopkg.in/mgo.v2/bson"
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

	token.Claims = jwt.MapClaims{
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
		if token.Claims.(jwt.MapClaims)["userId"] != nil {
			claims.UserID = token.Claims.(jwt.MapClaims)["userId"].(string)
		}
		if token.Claims.(jwt.MapClaims)["jti"] != nil {
			claims.JTI = token.Claims.(jwt.MapClaims)["jti"].(string)
		}
		if token.Claims.(jwt.MapClaims)["iat"] != nil {
			claims.IssuedAt, _ = time.Parse(time.RFC3339, token.Claims.(jwt.MapClaims)["iat"].(string))
		}
		if token.Claims.(jwt.MapClaims)["exp"] != nil {
			claims.ExpireAt, _ = time.Parse(time.RFC3339, token.Claims.(jwt.MapClaims)["exp"].(string))
		}
	}

	return token, &claims, err
}
