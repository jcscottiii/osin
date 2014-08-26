package osin

import (
	"errors"
	"net/http"
	"time"
)

// AccessRequestType is the type for OAuth param `grant_type`
type AccessRequestType string

const (
	AUTHORIZATION_CODE AccessRequestType = "authorization_code"
	REFRESH_TOKEN                        = "refresh_token"
	PASSWORD                             = "password"
	CLIENT_CREDENTIALS                   = "client_credentials"
	ASSERTION                            = "assertion"
	IMPLICIT                             = "__implicit"
)

// AccessRequest is a request for access tokens
type AccessRequest struct {
	Type          AccessRequestType
	Code          string
	Id            string
	AuthorizeDataCode string
	PreviousAccessToken, PreviousRefreshToken string
	RedirectUri   string
	Scope         string
	Username      string
	Password      string
	AssertionType string
	Assertion     string

	// Set if request is authorized
	Authorized bool

	// Token expiration in seconds. Change if different from default
	Expiration int32

	// Set if a refresh token should be generated
	GenerateRefresh bool
}

// AccessData represents an access grant (tokens, expiration, client, etc)
type AccessData struct {
	// Client information
	Id string

	// Authorize data, for authorization code
	AuthorizeDataCode string

	// Previous access data, for refresh token
	PreviousAccessToken, PreviousRefreshToken string

	// Access token
	AccessToken string

	// Refresh Token. Can be blank
	RefreshToken string

	// Token expiration in seconds
	ExpiresIn int32

	// Requested scope
	Scope string

	// Redirect Uri from request
	RedirectUri string

	// Date created
	CreatedAt time.Time
}

// IsExpired returns true if access expired
func (d *AccessData) IsExpired() bool {
	return d.CreatedAt.Add(time.Duration(d.ExpiresIn) * time.Second).Before(time.Now())
}

// ExpireAt returns the expiration date
func (d *AccessData) ExpireAt() time.Time {
	return d.CreatedAt.Add(time.Duration(d.ExpiresIn) * time.Second)
}

// AccessTokenGen generates access tokens
type AccessTokenGen interface {
	GenerateAccessToken(data *AccessData, generaterefresh bool) (accesstoken string, refreshtoken string, err error)
}

// HandleAccessRequest is the http.HandlerFunc for handling access token requests
func (s *Server) HandleAccessRequest(w *Response, r *http.Request) *AccessRequest {
	// Only allow GET or POST
	if r.Method == "GET" {
		if !s.Config.AllowGetAccessRequest {
			w.SetError(E_INVALID_REQUEST, "")
			w.InternalError = errors.New("Request must be POST")
			return nil
		}
	} else if r.Method != "POST" {
		w.SetError(E_INVALID_REQUEST, "")
		w.InternalError = errors.New("Request must be POST")
		return nil
	}

	err := r.ParseForm()
	if err != nil {
		w.SetError(E_INVALID_REQUEST, "")
		w.InternalError = err
		return nil
	}

	grantType := AccessRequestType(r.Form.Get("grant_type"))
	if s.Config.AllowedAccessTypes.Exists(grantType) {
		switch grantType {
		case AUTHORIZATION_CODE:
			return s.handleAuthorizationCodeRequest(w, r)
		case REFRESH_TOKEN:
			return s.handleRefreshTokenRequest(w, r)
		case PASSWORD:
			return s.handlePasswordRequest(w, r)
		case CLIENT_CREDENTIALS:
			return s.handleClientCredentialsRequest(w, r)
		case ASSERTION:
			return s.handleAssertionRequest(w, r)
		}
	}

	w.SetError(E_UNSUPPORTED_GRANT_TYPE, "")
	return nil
}

func (s *Server) handleAuthorizationCodeRequest(w *Response, r *http.Request) *AccessRequest {
	// get client authentication
	auth := getClientAuth(w, r, s.Config.AllowClientSecretInParams)
	if auth == nil {
		return nil
	}

	// generate access token
	ret := &AccessRequest{
		Type:            AUTHORIZATION_CODE,
		Code:            r.Form.Get("code"),
		RedirectUri:     r.Form.Get("redirect_uri"),
		GenerateRefresh: true,
		Expiration:      s.Config.AccessExpiration,
	}

	// "code" is required
	if ret.Code == "" {
		w.SetError(E_INVALID_GRANT, "")
		return nil
	}

	// must have a valid client
	var client Client
	if client = getClient(auth, w.Storage, w, r); client == nil {
		return nil
	}

	// must be a valid authorization code
	var err error
	var authorizeData *AuthorizeData
	authorizeData, err = w.Storage.LoadAuthorize(ret.Code, r)
	if err != nil {
		w.SetError(E_INVALID_GRANT, "")
		w.InternalError = err
		return nil
	}
	if authorizeData == nil {
		w.SetError(E_UNAUTHORIZED_CLIENT, "")
		return nil
	}
	if client.GetId() == "" {
		w.SetError(E_UNAUTHORIZED_CLIENT, "")
		return nil
	}
	if client.GetRedirectUri() == "" {
		w.SetError(E_UNAUTHORIZED_CLIENT, "")
		return nil
	}
	if authorizeData.IsExpired() {
		w.SetError(E_INVALID_GRANT, "")
		return nil
	}

	// code must be from the client
	if authorizeData.Id != client.GetId() {
		w.SetError(E_INVALID_GRANT, "")
		return nil
	}

	// check redirect uri
	if ret.RedirectUri == "" {
		ret.RedirectUri = client.GetRedirectUri()
	}
	if err = ValidateUri(client.GetRedirectUri(), ret.RedirectUri); err != nil {
		w.SetError(E_INVALID_REQUEST, "")
		w.InternalError = err
		return nil
	}
	if authorizeData.RedirectUri != ret.RedirectUri {
		w.SetError(E_INVALID_REQUEST, "")
		w.InternalError = errors.New("Redirect uri is different")
		return nil
	}

	// set rest of data
	ret.Id = client.GetId()
	ret.AuthorizeDataCode = authorizeData.Code
	ret.Scope = authorizeData.Scope

	return ret
}

func (s *Server) handleRefreshTokenRequest(w *Response, r *http.Request) *AccessRequest {
	// get client authentication
	auth := getClientAuth(w, r, s.Config.AllowClientSecretInParams)
	if auth == nil {
		return nil
	}

	// generate access token
	ret := &AccessRequest{
		Type:            REFRESH_TOKEN,
		Code:            r.Form.Get("refresh_token"),
		Scope:           r.Form.Get("scope"),
		GenerateRefresh: true,
		Expiration:      s.Config.AccessExpiration,
	}

	// "refresh_token" is required
	if ret.Code == "" {
		w.SetError(E_INVALID_GRANT, "")
		return nil
	}

	// must have a valid client
	var client Client
	if client = getClient(auth, w.Storage, w, r); client == nil {
		return nil
	}

	// must be a valid refresh code
	var err error
	var accessData *AccessData
	accessData, err = w.Storage.LoadRefresh(ret.Code, r)
	if err != nil {
		w.SetError(E_INVALID_GRANT, "")
		w.InternalError = err
		return nil
	}
	if accessData == nil {
		w.SetError(E_UNAUTHORIZED_CLIENT, "")
		return nil
	}
	if accessData.Id == "" {
		w.SetError(E_UNAUTHORIZED_CLIENT, "")
		return nil
	}
	if accessData.RedirectUri == "" {
		w.SetError(E_UNAUTHORIZED_CLIENT, "")
		return nil
	}
	if client.GetId() == "" {
		w.SetError(E_UNAUTHORIZED_CLIENT, "")
		return nil
	}
	if client.GetRedirectUri() == "" {
		w.SetError(E_UNAUTHORIZED_CLIENT, "")
		return nil
	}

	// client must be the same as the previous token
	if accessData.Id != client.GetId() {
		w.SetError(E_INVALID_CLIENT, "")
		w.InternalError = errors.New("Client id must be the same from previous token")
		return nil

	}

	// set rest of data
	ret.Id = client.GetId()
	ret.RedirectUri = accessData.RedirectUri
	if ret.Scope == "" {
		ret.Scope = accessData.Scope
	}

	return ret
}

func (s *Server) handlePasswordRequest(w *Response, r *http.Request) *AccessRequest {
	// get client authentication
	auth := getClientAuth(w, r, s.Config.AllowClientSecretInParams)
	if auth == nil {
		return nil
	}

	// generate access token
	ret := &AccessRequest{
		Type:            PASSWORD,
		Username:        r.Form.Get("username"),
		Password:        r.Form.Get("password"),
		Scope:           r.Form.Get("scope"),
		GenerateRefresh: true,
		Expiration:      s.Config.AccessExpiration,
	}

	// "username" and "password" is required
	if ret.Username == "" || ret.Password == "" {
		w.SetError(E_INVALID_GRANT, "")
		return nil
	}

	// must have a valid client
	var client Client
	if client = getClient(auth, w.Storage, w, r); client == nil {
		return nil
	}

	if client.GetId() == "" {
		w.SetError(E_UNAUTHORIZED_CLIENT, "")
		return nil
	}
	ret.Id = client.GetId()

	// set redirect uri
	ret.RedirectUri = client.GetRedirectUri()

	return ret
}

func (s *Server) handleClientCredentialsRequest(w *Response, r *http.Request) *AccessRequest {
	// get client authentication
	auth := getClientAuth(w, r, s.Config.AllowClientSecretInParams)
	if auth == nil {
		return nil
	}

	// generate access token
	ret := &AccessRequest{
		Type:            CLIENT_CREDENTIALS,
		Scope:           r.Form.Get("scope"),
		GenerateRefresh: true,
		Expiration:      s.Config.AccessExpiration,
	}

	// must have a valid client
	var client Client
	if client = getClient(auth, w.Storage, w, r); client == nil {
		return nil
	}

	if client.GetId() == "" {
		w.SetError(E_UNAUTHORIZED_CLIENT, "")
		return nil
	}
	ret.Id = client.GetId()

	// set redirect uri
	ret.RedirectUri = client.GetRedirectUri()

	return ret
}

func (s *Server) handleAssertionRequest(w *Response, r *http.Request) *AccessRequest {
	// get client authentication
	auth := getClientAuth(w, r, s.Config.AllowClientSecretInParams)
	if auth == nil {
		return nil
	}

	// generate access token
	ret := &AccessRequest{
		Type:            ASSERTION,
		Scope:           r.Form.Get("scope"),
		AssertionType:   r.Form.Get("assertion_type"),
		Assertion:       r.Form.Get("assertion"),
		GenerateRefresh: false, // assertion should NOT generate a refresh token, per the RFC
		Expiration:      s.Config.AccessExpiration,
	}

	// "assertion_type" and "assertion" is required
	if ret.AssertionType == "" || ret.Assertion == "" {
		w.SetError(E_INVALID_GRANT, "")
		return nil
	}

	// must have a valid client
	var client Client
	if client = getClient(auth, w.Storage, w, r); client == nil {
		return nil
	}

	if client.GetId() == "" {
		w.SetError(E_UNAUTHORIZED_CLIENT, "")
		return nil
	}
	ret.Id = client.GetId()

	// set redirect uri
	ret.RedirectUri = client.GetRedirectUri()

	return ret
}

func (s *Server) FinishAccessRequest(w *Response, r *http.Request, ar *AccessRequest) {
	// don't process if is already an error
	if w.IsError {
		return
	}
	redirectUri := r.Form.Get("redirect_uri")
	// Get redirect uri from AccessRequest if it's there (e.g., refresh token request)
	if ar.RedirectUri != "" {
		redirectUri = ar.RedirectUri
	}
	if ar.Authorized {
		// generate access token
		ret := &AccessData{
			Id:            ar.Id,
			AuthorizeDataCode: ar.AuthorizeDataCode,
			PreviousAccessToken:    ar.PreviousAccessToken,
			PreviousRefreshToken:    ar.PreviousRefreshToken,
			RedirectUri:   redirectUri,
			CreatedAt:     time.Now(),
			ExpiresIn:     ar.Expiration,
			Scope:         ar.Scope,
		}

		var err error

		// generate access token
		ret.AccessToken, ret.RefreshToken, err = s.AccessTokenGen.GenerateAccessToken(ret, ar.GenerateRefresh)
		if err != nil {
			w.SetError(E_SERVER_ERROR, "")
			w.InternalError = err
			return
		}

		// save access token
		if err = w.Storage.SaveAccess(ret, r); err != nil {
			w.SetError(E_SERVER_ERROR, "")
			w.InternalError = err
			return
		}

		// remove authorization token
		if ret.AuthorizeDataCode != "" {
			w.Storage.RemoveAuthorize(ret.AuthorizeDataCode, r)
		}

		// remove previous access token
		if ret.PreviousRefreshToken != "" {
			w.Storage.RemoveRefresh(ret.PreviousRefreshToken, r)
		}
		if ret.PreviousAccessToken != "" {
			w.Storage.RemoveAccess(ret.PreviousAccessToken, r)
		}

		// output data
		w.Output["access_token"] = ret.AccessToken
		w.Output["token_type"] = s.Config.TokenType
		w.Output["expires_in"] = ret.ExpiresIn
		if ret.RefreshToken != "" {
			w.Output["refresh_token"] = ret.RefreshToken
		}
		if ar.Scope != "" {
			w.Output["scope"] = ar.Scope
		}
	} else {
		w.SetError(E_ACCESS_DENIED, "")
	}
}

// Helper Functions

// getClient looks up and authenticates the basic auth using the given
// storage. Sets an error on the response if auth fails or a server error occurs.
func getClient(auth *BasicAuth, storage Storage, w *Response, r *http.Request) Client {
	client, err := storage.GetClient(auth.Username, r)
	if err != nil {
		w.SetError(E_SERVER_ERROR, "")
		w.InternalError = err
		return nil
	}
	if client == nil {
		w.SetError(E_UNAUTHORIZED_CLIENT, "")
		return nil
	}
	if client.GetSecret() != auth.Password {
		w.SetError(E_UNAUTHORIZED_CLIENT, "")
		return nil
	}
	if client.GetRedirectUri() == "" {
		w.SetError(E_UNAUTHORIZED_CLIENT, "")
		return nil
	}
	return client
}
