package osin

import (
	"net/http"
)

// Storage interface
type Storage interface {
	// Clone the storage if needed. For example, using mgo, you can clone the session with session.Clone
	// to avoid concurrent access problems.
	// This is to avoid cloning the connection at each method access.
	// Can return itself if not a problem.
	Clone() Storage

	// Close the resources the Storate potentially holds (using Clone for example)
	Close()

	// GetClient loads the client by id (client_id)
	GetClient(id string, r *http.Request) (Client, error)

	// SaveAuthorize saves authorize data.
	SaveAuthorize(d *AuthorizeData, r *http.Request) error

	// LoadAuthorize looks up AuthorizeData by a code.
	// Client information MUST be loaded together.
	// Optionally can return error if expired.
	LoadAuthorize(code string, r *http.Request) (*AuthorizeData, error)

	// RemoveAuthorize revokes or deletes the authorization code.
	RemoveAuthorize(code string, r *http.Request) error

	// SaveAccess writes AccessData.
	// If RefreshToken is not blank, it must save in a way that can be loaded using LoadRefresh.
	SaveAccess(d *AccessData, r *http.Request) error

	// LoadAccess retrieves access data by token. Client information MUST be loaded together.
	// AuthorizeData and AccessData DON'T NEED to be loaded if not easily available.
	// Optionally can return error if expired.
	LoadAccess(token string, r *http.Request) (*AccessData, error)

	// RemoveAccess revokes or deletes an AccessData.
	RemoveAccess(token string, r *http.Request) error

	// LoadRefresh retrieves refresh AccessData. Client information MUST be loaded together.
	// AuthorizeData and AccessData DON'T NEED to be loaded if not easily available.
	// Optionally can return error if expired.
	LoadRefresh(token string, r *http.Request) (*AccessData, error)

	// RemoveRefresh revokes or deletes refresh AccessData.
	RemoveRefresh(token string, r *http.Request) error
}
