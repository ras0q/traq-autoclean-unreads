package main

import (
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/gob"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/ext"
	"github.com/google/uuid"
	"github.com/gorilla/sessions"
	"github.com/traPtitech/go-traq"
	traqoauth2 "github.com/traPtitech/go-traq-oauth2"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
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

var apiClient = traq.NewAPIClient(traq.NewConfiguration())
var botAccessToken = os.Getenv("TRAQ_BOT_ACCESS_TOKEN")

var mongoClient *mongo.Client
var mongoURI = os.Getenv("MONGODB_URI")
var dbName = os.Getenv("MONGODB_DATABASE")

const collectionNameToken = "tokens"
const collectionNameSetting = "settings"

type TokenSchema struct {
	ID           uuid.UUID `bson:"_id"` // traQ userID
	AccessToken  string
	TokenType    string
	RefreshToken string
	Expiry       time.Time
}

type SettingSchema struct {
	ID     uuid.UUID `bson:"_id"` // traQ userID
	Filter string    // CEL (https://cel.dev/) evaluation
}

type CELInput struct {
	Channel  traq.UnreadChannel
	Messages []traq.Message
	UserMap  map[string]traq.User
}

var celEnv, _ = cel.NewEnv(
	cel.Variable("input", cel.ObjectType("main.CELInput")),
	ext.NativeTypes(
		reflect.TypeFor[CELInput](),
		reflect.TypeFor[traq.Message](),
		reflect.TypeFor[traq.User](),
	),
)

//go:embed index.html
var indexHTML string

func main() {
	// Register oauth2.Token to gob for session
	gob.Register(&oauth2.Token{})

	// slog.SetLogLoggerLevel(slog.LevelDebug)

	_mongoClient, err := mongo.Connect(context.Background(),
		options.
			Client().
			ApplyURI(
				fmt.Sprintf(
					"mongodb://%s:%s@%s:%s/%s",
					url.QueryEscape(os.Getenv("MONGODB_USER")),
					url.QueryEscape(os.Getenv("MONGODB_PASSWORD")),
					url.PathEscape(os.Getenv("MONGODB_HOSTNAME")),
					os.Getenv("MONGODB_PORT"),
					url.QueryEscape(dbName),
				),
			),
	)
	if err != nil {
		panic(err)
	}
	mongoClient = _mongoClient
	defer func() {
		if err := mongoClient.Disconnect(context.Background()); err != nil {
			panic(err)
		}
	}()

	go runClearner()

	http.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, indexHTML)
	})
	http.HandleFunc("POST /oauth2/authorize", authorizeHandler)
	http.HandleFunc("GET /oauth2/callback", callbackHandler)

	slog.Info("Server starting...", "addr", addr)
	panic(http.ListenAndServe(addr, nil)) // TODO: graceful shutdown
}

func runClearner() {
	ticker := time.NewTicker(time.Minute) // TODO: use WebSocket
	for {
		t := <-ticker.C

		ctx := context.Background()

		collection := mongoClient.Database(dbName).Collection(collectionNameToken)
		cursor, err := collection.Find(ctx, bson.D{})
		if err != nil {
			slog.Error("find tokens", "err", err)
			continue
		}

		var tokens []TokenSchema
		if err := cursor.All(ctx, &tokens); err != nil {
			slog.Error("iterate cursor", "err", err)
			continue
		}

		slog.Debug("tick start", "time", t, "#tokens", len(tokens))

		if len(tokens) == 0 {
			continue
		}

		collection = mongoClient.Database(dbName).Collection(collectionNameSetting)
		cursor, err = collection.Find(ctx, bson.D{})
		if err != nil {
			slog.Error("find tokens", "err", err)
			continue
		}

		var settings []SettingSchema
		if err := cursor.All(ctx, &settings); err != nil {
			slog.Error("iterate cursor", "err", err)
			continue
		}

		settingMap := make(map[string]SettingSchema, len(settings))
		for _, setting := range settings {
			settingMap[setting.ID.String()] = setting
		}

		ctx = context.WithValue(ctx, traq.ContextAccessToken, botAccessToken)
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

		for _, token := range tokens {
			ctx := context.Background()
			tokenSource := oauth2Config.TokenSource(ctx, &oauth2.Token{
				AccessToken:  token.AccessToken,
				TokenType:    token.TokenType,
				RefreshToken: token.RefreshToken,
				Expiry:       token.Expiry,
			})
			ctx = context.WithValue(ctx, traq.ContextOAuth2, tokenSource)

			filter := "input.Channel.Count > 0 && !input.Channel.Noticeable && input.Messages.all(m, input.UserMap[m.UserId].Bot)"
			setting, ok := settingMap[token.ID.String()]
			if ok && len(setting.Filter) > 0 {
				filter = setting.Filter
			}
			go clearUnreadMessages(ctx, token.ID.String(), userMap, filter)
		}
	}
}

func clearUnreadMessages(ctx context.Context, userID string, userMap map[string]traq.User, celFilter string) {
	myUnreadChannels, resp, err := apiClient.MeApi.GetMyUnreadChannels(ctx).Execute()
	if err != nil || resp.StatusCode != http.StatusOK {
		l := slog.With("err", err)
		if resp != nil {
			l = l.With("status", resp.Status, "statusCode", resp.StatusCode)
		}
		l.ErrorContext(ctx, "get my unread channels", "err", err)

		notifyFromBot(userID, "BOT未読を自動で消化するために再認可を行ってください")
		collection := mongoClient.Database(dbName).Collection(collectionNameToken)
		filter := bson.D{{Key: "userID", Value: userID}}
		if _, err := collection.DeleteOne(ctx, filter); err != nil {
			slog.ErrorContext(ctx, "delete token collection", "err", err)
		}

		return
	}

	for _, channel := range myUnreadChannels {
		if channel.Count == 0 || channel.Noticeable {
			continue
		}

		l := slog.With("channelId", channel.ChannelId)

		messages, resp, err := apiClient.ChannelApi.GetMessages(ctx, channel.ChannelId).Limit(channel.Count).Since(channel.Since).Inclusive(true).Execute()
		if err != nil {
			l.ErrorContext(ctx, "get my unread messages", "err", err)
			return
		} else if resp.StatusCode != http.StatusOK {
			l.ErrorContext(ctx, "get my unread messages", "status", resp.Status, "statusCode", resp.StatusCode)
			return
		}

		canClearMessages, err := evaluateCEL(ctx, celFilter, CELInput{
			Channel:  channel,
			Messages: messages,
			UserMap:  userMap,
		})
		if err != nil {
			l.ErrorContext(ctx, "evaluate CEL", "err", err)
			return
		}
		if !canClearMessages {
			continue
		}

		resp, err = apiClient.MeApi.ReadChannel(ctx, channel.ChannelId).Execute()
		if err != nil {
			l.ErrorContext(ctx, "clear unread messages", "err", err)
			return
		} else if resp.StatusCode != http.StatusNoContent {
			l.ErrorContext(ctx, "clear unread messages", "status", resp.Status, "statusCode", resp.StatusCode)
			return
		}
	}
}

func notifyFromBot(userID string, content string) {
	ctx := context.WithValue(context.Background(), traq.ContextAccessToken, botAccessToken)
	_, resp, err := apiClient.MessageApi.PostDirectMessage(ctx, userID).
		PostMessageRequest(traq.PostMessageRequest{Content: content}).
		Execute()
	if err != nil {
		slog.ErrorContext(ctx, "post bot message", "err", err)
	} else if resp.StatusCode != http.StatusNoContent {
		slog.ErrorContext(ctx, "post bot message", "status", resp.Status, "statusCode", resp.StatusCode)
	}
}

func evaluateCEL(ctx context.Context, celProgram string, input CELInput) (bool, error) {
	ast, iss := celEnv.Compile(celProgram)
	if err := iss.Err(); err != nil {
		return false, err
	}

	prg, err := celEnv.Program(ast)
	if err != nil {
		return false, err
	}

	output, _, err := prg.ContextEval(ctx, map[string]any{"input": input})
	if err != nil {
		return false, err
	}

	outputBool, ok := output.Value().(bool)
	if !ok {
		return false, fmt.Errorf("output of the program must be a boolean type")
	}

	return outputBool, nil
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

	ctx := r.Context()
	tokenSource := oauth2Config.TokenSource(ctx, token)
	ctx = context.WithValue(ctx, traq.ContextOAuth2, tokenSource)
	myUser, resp, err := apiClient.MeApi.GetMe(ctx).Execute()
	if err != nil {
		internalHTTPError(w, err, "failed to get my user info")
		return
	} else if resp.StatusCode != http.StatusOK {
		internalHTTPError(w, fmt.Errorf("invalid status: %d", resp.StatusCode), "failed to get my user info")
		return
	}

	collection := mongoClient.Database(dbName).Collection(collectionNameToken)
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
