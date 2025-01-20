package handler

import (
	"cmp"
	"context"
	"crypto/rand"
	"embed"
	_ "embed"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"os"

	"github.com/google/uuid"
	"github.com/gorilla/sessions"
	"github.com/ras0q/traq-autoclean-unreads/internal/filter"
	"github.com/ras0q/traq-autoclean-unreads/internal/repository"
	"github.com/traPtitech/go-traq"
	traqoauth2 "github.com/traPtitech/go-traq-oauth2"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/oauth2"
)

type Handler struct {
	SessionName  string
	StateLength  int
	SessionStore *sessions.CookieStore
	DB           *mongo.Database
	APIClient    *traq.APIClient
}

// Configure at https://bot-console.trap.jp/clients
var OAuth2Config = oauth2.Config{
	ClientID:     os.Getenv("TRAQ_CLIENT_ID"),
	ClientSecret: os.Getenv("TRAQ_CLIENT_SECRET"),
	Endpoint:     traqoauth2.Prod, // or traqoauth2.Staging
	RedirectURL:  os.Getenv("TRAQ_REDIRECT_URL"),
	Scopes:       []string{traqoauth2.ScopeRead, traqoauth2.ScopeWrite},
}

// TODO: move this
const defaultFilter = `input.Channel.Count > 0
&& !input.Channel.Noticeable
&& input.Channel.ChannelId in input.PublicChannelMap
&& input.Messages.all(m, input.UserMap[m.UserId].Bot)`

//go:embed index.html
var fs embed.FS

type templateData struct {
	UserID    string
	CELFilter string
}

func (h *Handler) Index(w http.ResponseWriter, r *http.Request) {
	session, err := h.SessionStore.Get(r, h.SessionName)
	if err != nil {
		internalHTTPError(w, err, "failed to get session")
		return
	}

	var userID string
	if _userID, ok := session.Values["user_id"]; ok {
		userID = _userID.(string)
	}

	var setting repository.SettingSchema
	collection := h.DB.Collection("settings")
	err = collection.FindOne(r.Context(), bson.D{{Key: "_id", Value: userID}}).Decode(&setting)
	if err != nil && !errors.Is(err, mongo.ErrNoDocuments) {
		internalHTTPError(w, err, "failed to get setting")
		return
	}

	tmpl, err := template.ParseFS(fs, "index.html")
	if err != nil {
		internalHTTPError(w, err, "failed to parse template")
		return
	}

	err = tmpl.Execute(w, templateData{
		UserID:    userID,
		CELFilter: cmp.Or(setting.Filter, filter.DefaultCELFilter),
	})
	if err != nil {
		internalHTTPError(w, err, "failed to execute template")
		return
	}
}

func (h *Handler) Authorize(w http.ResponseWriter, r *http.Request) {
	session, err := h.SessionStore.Get(r, h.SessionName)
	if err != nil {
		internalHTTPError(w, err, "failed to get session")
		return
	}

	codeVerifier := oauth2.GenerateVerifier()
	session.Values["code_verifier"] = codeVerifier

	state := make([]byte, h.StateLength)
	_, _ = rand.Read(state)
	session.Values["state"] = string(state)

	if err := session.Save(r, w); err != nil {
		internalHTTPError(w, err, "failed to save session")
		return
	}

	// this client forces to use PKCE
	// code_challenge_method = S256 is set by S256ChallengeOption
	authCodeURL := OAuth2Config.AuthCodeURL(
		string(state),
		oauth2.S256ChallengeOption(codeVerifier),
	)

	// HTMX support
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Add("HX-Redirect", authCodeURL)
		return
	}

	http.Redirect(w, r, authCodeURL, http.StatusFound)
}

func (h *Handler) Callback(w http.ResponseWriter, r *http.Request) {
	// query parameters
	var (
		code  = r.URL.Query().Get("code")
		state = r.URL.Query().Get("state")
	)

	if code == "" {
		http.Error(w, "code is empty", http.StatusBadRequest)
		return
	}

	session, err := h.SessionStore.Get(r, h.SessionName)
	if err != nil {
		internalHTTPError(w, err, "failed to get session")
		return
	}

	codeVerifier, ok := session.Values["code_verifier"]
	if !ok {
		http.Error(w, "invalid session", http.StatusBadRequest)
		return
	}

	if storedState, ok := session.Values["state"]; !ok || storedState.(string) != state {
		http.Error(w, "invalid state", http.StatusBadRequest)
		return
	}

	token, err := OAuth2Config.Exchange(
		r.Context(),
		code,
		oauth2.VerifierOption(codeVerifier.(string)),
	)
	if err != nil {
		internalHTTPError(w, err, "failed to exchange token")
		return
	}

	ctx := r.Context()
	tokenSource := OAuth2Config.TokenSource(ctx, token)
	ctx = context.WithValue(ctx, traq.ContextOAuth2, tokenSource)
	myUser, resp, err := h.APIClient.MeApi.GetMe(ctx).Execute()
	if err != nil {
		internalHTTPError(w, err, "failed to get my user info")
		return
	} else if resp.StatusCode != http.StatusOK {
		internalHTTPError(w, fmt.Errorf("invalid status: %d", resp.StatusCode), "failed to get my user info")
		return
	}

	collection := h.DB.Collection("tokens")
	update := bson.D{{
		Key: "$set",
		Value: bson.D{
			{Key: "_id", Value: uuid.MustParse(myUser.Id)},
			{Key: "accessToken", Value: token.AccessToken},
			{Key: "tokenType", Value: token.TokenType},
			{Key: "refreshToken", Value: token.RefreshToken},
			{Key: "expiry", Value: token.Expiry},
		},
	}}
	opts := options.Update().SetUpsert(true)
	if _, err := collection.UpdateByID(ctx, uuid.MustParse(myUser.Id), update, opts); err != nil {
		internalHTTPError(w, err, "failed to insert tokencollection")
		return
	}

	session.Values["token"] = token
	session.Values["user_id"] = myUser.Id
	session.Values["username"] = myUser.Name
	if err := session.Save(r, w); err != nil {
		internalHTTPError(w, err, "failed to save session")
		return
	}

	// HTMX support
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Add("HX-Redirect", "/")
		return
	}

	http.Redirect(w, r, "/", http.StatusFound)
}

func (h *Handler) PutSetting(w http.ResponseWriter, r *http.Request) {
	session, err := h.SessionStore.Get(r, h.SessionName)
	if err != nil {
		internalHTTPError(w, err, "failed to get session")
		return
	}

	_userID, ok := session.Values["user_id"]
	if !ok {
		http.Error(w, "invalid session", http.StatusBadRequest)
		return
	}

	userID := uuid.MustParse(_userID.(string))

	if err := r.ParseForm(); err != nil {
		http.Error(w, "failed to parse form", http.StatusBadRequest)
		return
	}

	celFilter := r.Form.Get("filter")
	if len(celFilter) == 0 {
		http.Error(w, "filter is empty", http.StatusBadRequest)
		return
	}

	if _, iss := filter.CELEnv.Compile(celFilter); iss.Err() != nil {
		http.Error(w, fmt.Sprintf("Failed to compile CEL program:\n%s", iss), http.StatusBadRequest)
		return
	}

	collection := h.DB.Collection("settings")
	update := bson.D{{
		Key: "$set",
		Value: bson.D{
			{Key: "_id", Value: userID},
			{Key: "filter", Value: celFilter},
		},
	}}
	opts := options.Update().SetUpsert(true)
	if _, err := collection.UpdateByID(r.Context(), userID, update, opts); err != nil {
		internalHTTPError(w, err, "failed to insert tokencollection")
		return
	}
}

func internalHTTPError(w http.ResponseWriter, err error, msg string) {
	slog.Error("Internal Server Error", "err", err, "msg", msg)
	http.Error(w, msg, http.StatusInternalServerError)
}
