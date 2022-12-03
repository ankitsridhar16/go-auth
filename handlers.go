package main

import (
	"ankitsridhar/auth/repository"
	"context"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"time"
)

const (
	SessionCookieName = "session_token"
)

// TODO: Convert to a DB.
var users = map[string]string{
	"user1": "password1",
	"user2": "password2",
}

// TODO: Covert to a DB.
var sessions = map[string]session{}

// Session struct for storing session data for a user.
type session struct {
	username string
	expiry   time.Time
}

// Credentials struct for parsing credentials json data to proper types.
type Credentials struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

// Function to check if the session has expired or not.
func (s session) isExpired() bool {
	return s.expiry.Before(time.Now())
}

func Signup(w http.ResponseWriter, r *http.Request) {
	var ctx context.Context
	var creds Credentials
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	userExits := repository.CheckIfUserEmailExists(ctx, creds.Email)
	if userExits == true {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	hashedPassword, errHash := bcrypt.GenerateFromPassword([]byte(creds.Password), 16)
	if errHash != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	userSignedUp, errSignup := repository.Signup(ctx, creds.Username, creds.Email, string(hashedPassword))
	if errSignup != nil && userSignedUp == false {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	sessionToken := uuid.NewString()
	expiresAt := time.Now().Add(120 * time.Second)
	userSessionCreated, errCreateSession := repository.CreateUserSession(ctx, sessionToken,
		creds.Username, creds.Email, expiresAt)
	if errCreateSession != nil && userSessionCreated == false {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:    SessionCookieName,
		Value:   sessionToken,
		Expires: expiresAt,
	})
}

// Signin handler decodes the request body validates the password and
// generates a new session for the user and returns a cookie with session token.
func Signin(w http.ResponseWriter, r *http.Request) {
	var creds Credentials
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	expectedPassword, ok := users[creds.Username]
	if !ok || expectedPassword != creds.Password {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	sessionToken := uuid.NewString()
	expiresAt := time.Now().Add(120 * time.Second)
	sessions[sessionToken] = session{
		username: creds.Username,
		expiry:   expiresAt,
	}

	http.SetCookie(w, &http.Cookie{
		Name:    SessionCookieName,
		Value:   sessionToken,
		Expires: expiresAt,
	})
}

// Welcome handler validates a cookie from the request header and checks for a valid session
// then prints a welcome message as a response
func Welcome(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(SessionCookieName)
	if err != nil {
		if err == http.ErrNoCookie {
			w.WriteHeader(http.StatusUnauthorized)
		}
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	sessionToken := cookie.Value

	userSession, exists := sessions[sessionToken]
	if !exists {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if userSession.isExpired() {
		delete(sessions, sessionToken)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	w.Write([]byte(fmt.Sprintf("Welcome %s!", userSession.username)))
}

// Refresh handler validates a cookie from headers and checks for a valid session based
// on the expiry and if session has expired generate a new session for the user.
func Refresh(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(SessionCookieName)
	if err != nil {
		if err == http.ErrNoCookie {
			w.WriteHeader(http.StatusUnauthorized)
		}
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	sessionToken := cookie.Value

	userSession, exists := sessions[sessionToken]
	if !exists {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if userSession.isExpired() {
		delete(sessions, sessionToken)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	newSessionToken := uuid.NewString()
	expiresAt := time.Now().Add(120 * time.Second)
	sessions[newSessionToken] = session{
		username: userSession.username,
		expiry:   expiresAt,
	}

	delete(sessions, sessionToken)

	http.SetCookie(w, &http.Cookie{
		Name:    SessionCookieName,
		Value:   newSessionToken,
		Expires: expiresAt,
	})
}

// Logout handler validates a cookie from a header and then delete the session for the user
// from the sessions list.
func Logout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(SessionCookieName)
	if err != nil {
		if err == http.ErrNoCookie {
			w.WriteHeader(http.StatusUnauthorized)
		}
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	sessionToken := cookie.Value

	delete(sessions, sessionToken)

	http.SetCookie(w, &http.Cookie{
		Name:    SessionCookieName,
		Value:   "",
		Expires: time.Now(),
	})
}
