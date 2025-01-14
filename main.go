package main

import (
	"context"
	"crypto/rand"
	"encoding/gob"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/gorilla/sessions"
	"github.com/traPtitech/go-traq"
	"github.com/traPtitech/go-traq-oauth2"
	"golang.org/x/oauth2"
)

const (
	sessionName = "session_name"
	stateLength = 16
	addr        = ":8080"
)

var store = sessions.NewCookieStore([]byte(os.Getenv("SESSION_KEY")))

// Configure at https://bot-console.trap.jp/clients
var oauth2Config = oauth2.Config{
	ClientID:     os.Getenv("TRAQ_CLIENT_ID"),
	ClientSecret: os.Getenv("TRAQ_CLIENT_SECRET"),
	Endpoint:     traqoauth2.Prod, // or traqoauth2.Staging
	RedirectURL:  os.Getenv("TRAQ_REDIRECT_URL"),
	Scopes:       []string{traqoauth2.ScopeRead, traqoauth2.ScopeWrite},
}

// TODO: use DB
var tokens = []*oauth2.Token{}

var apiClient = traq.NewAPIClient(traq.NewConfiguration())

func main() {
	// Register oauth2.Token to gob for session
	gob.Register(&oauth2.Token{})

	go func() {
		ticker := time.NewTicker(time.Minute) // TODO: use WebSocket
		for {
			t := <-ticker.C

			slog.Info("tick start", "time", t, "#tokens", len(tokens))

			if len(tokens) == 0 {
				continue
			}

			ctx := context.Background()
			tokenSource := oauth2Config.TokenSource(ctx, tokens[0])
			ctx = context.WithValue(ctx, traq.ContextOAuth2, tokenSource)
			users, resp, err := apiClient.UserApi.GetUsers(ctx).IncludeSuspended(true).Execute()
			if err != nil {
				slog.ErrorContext(ctx, "get users", "err", err)
			} else if resp.StatusCode != http.StatusOK {
				slog.ErrorContext(ctx, "get users", "status", resp.Status, "statusCode", resp.StatusCode)
			}

			userMap := make(map[string]traq.User, len(users))
			for _, user := range users {
				userMap[user.Id] = user
			}

			var wg sync.WaitGroup
			wg.Add(len(tokens))
			for _, token := range tokens {
				ctx := context.Background()
				tokenSource := oauth2Config.TokenSource(ctx, token)
				ctx = context.WithValue(ctx, traq.ContextOAuth2, tokenSource)
				go func(ctx context.Context) {
					clearUnreadMessages(ctx, userMap)
					wg.Done()
				}(ctx)
			}
			wg.Wait()
		}
	}()

	http.HandleFunc("/oauth2/authorize", authorizeHandler)
	http.HandleFunc("/oauth2/callback", callbackHandler)

	slog.Info("Server starting...", "addr", addr)
	go panic(http.ListenAndServe(addr, nil))

}

func authorizeHandler(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, sessionName)
	if err != nil {
		internalHTTPError(w, err, "failed to get session")
		return
	}

	codeVerifier := oauth2.GenerateVerifier()
	session.Values["code_verifier"] = codeVerifier

	state := make([]byte, stateLength)
	_, _ = rand.Read(state)
	session.Values["state"] = string(state)

	if err := session.Save(r, w); err != nil {
		internalHTTPError(w, err, "failed to save session")
		return
	}

	// this client forces to use PKCE
	// code_challenge_method = S256 is set by S256ChallengeOption
	authCodeURL := oauth2Config.AuthCodeURL(
		string(state),
		oauth2.S256ChallengeOption(codeVerifier),
	)

	http.Redirect(w, r, authCodeURL, http.StatusFound)
}

func callbackHandler(w http.ResponseWriter, r *http.Request) {
	// query parameters
	var (
		code  = r.URL.Query().Get("code")
		state = r.URL.Query().Get("state")
	)

	if code == "" {
		http.Error(w, "code is empty", http.StatusBadRequest)
		return
	}

	session, err := store.Get(r, sessionName)
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

	token, err := oauth2Config.Exchange(
		r.Context(),
		code,
		oauth2.VerifierOption(codeVerifier.(string)),
	)
	if err != nil {
		internalHTTPError(w, err, "failed to exchange token")
		return
	}

	tokens = append(tokens, token)

	session.Values["token"] = token
	if err := session.Save(r, w); err != nil {
		internalHTTPError(w, err, "failed to save session")
		return
	}

	_, _ = w.Write([]byte("正常に登録されました。定期的にBOT投稿のみの未読を自動で消化します。"))
}

func internalHTTPError(w http.ResponseWriter, err error, msg string) {
	slog.Error("Internal Server Error", "err", err, "msg", msg)
	http.Error(w, msg, http.StatusInternalServerError)
}

func clearUnreadMessages(ctx context.Context, userMap map[string]traq.User) {
	myUnreadChannels, resp, err := apiClient.MeApi.GetMyUnreadChannels(ctx).Execute()
	if err != nil {
		slog.ErrorContext(ctx, "get my unread channels", "err", err)
	} else if resp.StatusCode != http.StatusOK {
		slog.ErrorContext(ctx, "get my unread channels", "status", resp.Status, "statusCode", resp.StatusCode)
	}

	for _, channel := range myUnreadChannels {
		if channel.Count == 0 {
			continue
		}

		l := slog.With("channelId", channel.ChannelId)

		messages, resp, err := apiClient.ChannelApi.GetMessages(ctx, channel.ChannelId).Limit(channel.Count).Since(channel.Since).Inclusive(true).Execute()
		if err != nil {
			l.ErrorContext(ctx, "get my unread messages", "err", err)
		} else if resp.StatusCode != http.StatusOK {
			l.ErrorContext(ctx, "get my unread messages", "status", resp.Status, "statusCode", resp.StatusCode)
		}

		canClearMessages := true
		for _, message := range messages {
			user, ok := userMap[message.UserId]
			if !ok || !user.Bot {
				canClearMessages = false
				break
			}
		}
		if !canClearMessages {
			continue
		}

		resp, err = apiClient.MeApi.ReadChannel(ctx, channel.ChannelId).Execute()
		if err != nil {
			l.ErrorContext(ctx, "clear unread messages", "err", err)
		} else if resp.StatusCode != http.StatusNoContent {
			l.ErrorContext(ctx, "clear unread messages", "status", resp.Status, "statusCode", resp.StatusCode)
		}
	}
}
