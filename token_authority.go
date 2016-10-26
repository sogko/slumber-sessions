package sessions

import (
	. "github.com/grsouza/slumber-sessions/domain"

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
	tokenClaims := token.Claims.(jwt.MapClaims)
	if token.IsValid() {
		if tokenClaims["userId"] != nil {
			claims.UserID = tokenClaims["userId"].(string)
		}
		if tokenClaims["jti"] != nil {
			claims.JTI = tokenClaims["jti"].(string)
		}
		if tokenClaims["iat"] != nil {
			claims.IssuedAt, _ = time.Parse(time.RFC3339, tokenClaims["iat"].(string))
		}
		if tokenClaims["exp"] != nil {
			claims.ExpireAt, _ = time.Parse(time.RFC3339, tokenClaims["exp"].(string))
		}
	}

	return token, &claims, err
}
