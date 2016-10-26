package sessions

import (
	"encoding/json"
	"fmt"
	"github.com/grsouza/slumber/domain"
	"gopkg.in/mgo.v2/bson"
	"log"
	"net/http"
)

type GetSessionResponse_v0 struct {
	User    domain.IUser `json:"user"`
	Success bool         `json:"success"`
	Message string       `json:"message"`
}
type CreateSessionRequest_v0 struct {
	Username string `json:"username"`
	Password string `json:"password"`
}
type CreateSessionResponse_v0 struct {
	Token   string `json:"token"`
	Success bool   `json:"success"`
	Message string `json:"message"`
}
type DeleteSessionResponse_v0 struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}
type ErrorResponse_v0 struct {
	Message string `json:"message,omitempty"`
	Success bool   `json:"success"`
}

func (resource *Resource) DecodeRequestBody(w http.ResponseWriter, req *http.Request, target interface{}) error {
	decoder := json.NewDecoder(req.Body)
	err := decoder.Decode(target)
	if err != nil {
		resource.RenderError(w, req, http.StatusBadRequest, fmt.Sprintf("Request body parse error: %v", err.Error()))
		return err
	}
	return nil
}

func (resource *Resource) RenderError(w http.ResponseWriter, req *http.Request, status int, message string) {
	resource.Render(w, req, status, ErrorResponse_v0{
		Message: message,
		Success: false,
	})
}

func (resource *Resource) RenderUnauthorizedError(w http.ResponseWriter, req *http.Request, message string) {
	resource.Render(w, req, http.StatusUnauthorized, ErrorResponse_v0{
		Message: message,
		Success: false,
	})
}

// HandleGetSession_v0 Get session details
func (resource *Resource) HandleGetSession_v0(w http.ResponseWriter, req *http.Request) {
	ctx := resource.Context()
	user := ctx.GetCurrentUserCtx(req)

	resource.Render(w, req, http.StatusOK, GetSessionResponse_v0{
		User:    user,
		Success: true,
		Message: "Session details retrieved",
	})
}

// HandleCreateSession_v0 verify user's credentials and generates a JWT token if valid
func (resource *Resource) HandleCreateSession_v0(w http.ResponseWriter, req *http.Request) {
	ta := resource.TokenAuthority

	var body CreateSessionRequest_v0
	err := resource.DecodeRequestBody(w, req, &body)
	if err != nil {
		return
	}

	if body.Username == "" {
		resource.RenderError(w, req, http.StatusBadRequest, "Empty username")
		return
	}

	repo := resource.UserRepository(req)
	user, err := repo.GetUserByUsername(body.Username)
	if err != nil {
		resource.RenderError(w, req, http.StatusBadRequest, "Invalid username/password")
		return
	}

	if !user.IsCredentialsVerified(body.Password) {
		resource.RenderError(w, req, http.StatusBadRequest, "Invalid username/password")
		return
	}

	tokenString, err := ta.CreateNewSessionToken(
		NewTokenClaims(user.GetID()))

	if err != nil {
		resource.RenderError(w, req, http.StatusBadRequest, "Error creating session token")
		return
	}

	// run a post-create-session hook if defined
	if resource.ControllerHooks.PostCreateSessionHook != nil {
		err = resource.ControllerHooks.PostCreateSessionHook(resource, w, req, &PostCreateSessionHookPayload{
			TokenString: tokenString,
		})
		if err != nil {
			resource.RenderError(w, req, http.StatusBadRequest, err.Error())
			return
		}
	}

	// TODO: update user object with last logged-in

	resource.Render(w, req, http.StatusCreated, CreateSessionResponse_v0{
		Token:   tokenString,
		Success: true,
		Message: "Session token created",
	})
}

// HandleDeleteSession_v0 invalidates a session token
func (resource *Resource) HandleDeleteSession_v0(w http.ResponseWriter, req *http.Request) {
	ctx := resource.Context()
	claims := GetAuthenticatedClaimsCtx(ctx, req)
	//	hooks := ctx.GetControllerHooksMapCtx(req)

	if claims == nil || !bson.IsObjectIdHex(claims.GetJTI()) {
		// run a post-delete-session hook
		if resource.ControllerHooks.PostDeleteSessionHook != nil {
			err := resource.ControllerHooks.PostDeleteSessionHook(resource, w, req, &PostDeleteSessionHookPayload{
				Claims: claims,
			})
			if err != nil {
				resource.RenderError(w, req, http.StatusBadRequest, err.Error())
				return
			}
		}
		// simply return because we can't blacklist a token without identifier
		resource.Render(w, req, http.StatusOK, DeleteSessionResponse_v0{
			Success: true,
			Message: "Session removed",
		})
		return
	}
	repo := resource.RevokedTokenRepository(req)
	err := repo.CreateRevokedToken(&RevokedToken{
		ID:         bson.ObjectIdHex(claims.GetJTI()),
		ExpiryDate: claims.GetExpireAt(),
	})
	if err != nil {
		log.Println("HandleDeleteSession_v0: Failed to create revoked token", err.Error())
	}

	// run a post-delete-session hook{
	if resource.ControllerHooks.PostDeleteSessionHook != nil {
		err = resource.ControllerHooks.PostDeleteSessionHook(resource, w, req, &PostDeleteSessionHookPayload{
			Claims: claims,
		})
		if err != nil {
			resource.RenderError(w, req, http.StatusBadRequest, err.Error())
			return
		}
	}

	resource.Render(w, req, http.StatusOK, DeleteSessionResponse_v0{
		Success: true,
		Message: "Session removed",
	})
}
