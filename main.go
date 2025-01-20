package main

import (
	"context"
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
	"github.com/gorilla/sessions"
	"github.com/ras0q/traq-autoclean-unreads/internal/handler"
	"github.com/ras0q/traq-autoclean-unreads/internal/repository"
	"github.com/traPtitech/go-traq"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/oauth2"
)

const (
	addr = ":8080"
)

var apiClient = traq.NewAPIClient(traq.NewConfiguration())
var botAccessToken = os.Getenv("TRAQ_BOT_ACCESS_TOKEN")

var mongoClient *mongo.Client
var dbName = os.Getenv("MONGODB_DATABASE")

const collectionNameToken = "tokens"
const collectionNameSetting = "settings"

type CELInput struct {
	Channel          traq.UnreadChannel
	Messages         []traq.Message
	PublicChannelMap map[string]traq.Channel
	UserMap          map[string]traq.User
}

const defaultFilter = `input.Channel.Count > 0
&& !input.Channel.Noticeable
&& input.Channel.ChannelId in input.PublicChannelMap
&& input.Messages.all(m, input.UserMap[m.UserId].Bot)`

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

	h := handler.Handler{
		SessionName:  "session_name",
		StateLength:  16,
		SessionStore: sessions.NewCookieStore([]byte(os.Getenv("SESSION_KEY"))),
		DB:           mongoClient.Database(dbName),
		APIClient:    apiClient,
	}

	http.HandleFunc("GET /", h.Index)
	http.HandleFunc("POST /oauth2/authorize", h.Authorize)
	http.HandleFunc("GET /oauth2/callback", h.Callback)

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

		var tokens []repository.TokenSchema
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

		var settings []repository.SettingSchema
		if err := cursor.All(ctx, &settings); err != nil {
			slog.Error("iterate cursor", "err", err)
			continue
		}

		settingMap := make(map[string]repository.SettingSchema, len(settings))
		for _, setting := range settings {
			settingMap[setting.ID.String()] = setting
		}

		ctx = context.WithValue(ctx, traq.ContextAccessToken, botAccessToken)
		users, resp, err := apiClient.UserApi.GetUsers(ctx).IncludeSuspended(true).Execute()
		if err != nil {
			slog.ErrorContext(ctx, "get users", "err", err)
			continue
		} else if resp.StatusCode != http.StatusOK {
			slog.ErrorContext(ctx, "get users", "status", resp.Status, "statusCode", resp.StatusCode)
			continue
		}

		userMap := make(map[string]traq.User, len(users))
		for _, user := range users {
			userMap[user.Id] = user
		}

		channels, resp, err := apiClient.ChannelApi.GetChannels(ctx).Execute()
		if err != nil {
			slog.ErrorContext(ctx, "get channels", "err", err)
			continue
		} else if resp.StatusCode != http.StatusOK {
			slog.ErrorContext(ctx, "get channels", "status", resp.Status, "statusCode", resp.StatusCode)
			continue
		}

		publicChannelMap := make(map[string]traq.Channel, len(users))
		for _, channel := range channels.Public {
			publicChannelMap[channel.Id] = channel
		}

		for _, token := range tokens {
			ctx := context.Background()
			tokenSource := handler.OAuth2Config.TokenSource(ctx, &oauth2.Token{
				AccessToken:  token.AccessToken,
				TokenType:    token.TokenType,
				RefreshToken: token.RefreshToken,
				Expiry:       token.Expiry,
			})
			ctx = context.WithValue(ctx, traq.ContextOAuth2, tokenSource)

			filter := defaultFilter
			setting, ok := settingMap[token.ID.String()]
			if ok && len(setting.Filter) > 0 {
				filter = setting.Filter
			}
			go clearUnreadMessages(ctx, token.ID.String(), userMap, publicChannelMap, filter)
		}
	}
}

func clearUnreadMessages(ctx context.Context, userID string, userMap map[string]traq.User, publicChannelMap map[string]traq.Channel, celFilter string) {
	myUnreadChannels, resp, err := apiClient.MeApi.GetMyUnreadChannels(ctx).Execute()
	if err != nil || resp.StatusCode != http.StatusOK {
		l := slog.With("err", err)
		if resp != nil {
			l = l.With("status", resp.Status, "statusCode", resp.StatusCode)
		}
		l.ErrorContext(ctx, "get my unread channels", "err", err)

		notifyFromBot(userID, "BOT未読を自動で消化するために再認可を行ってください")
		collection := mongoClient.Database(dbName).Collection(collectionNameToken)
		filter := bson.D{{Key: "_id", Value: userID}}
		if _, err := collection.DeleteOne(ctx, filter); err != nil {
			slog.ErrorContext(ctx, "delete token collection", "err", err)
		}

		return
	}

	for _, channel := range myUnreadChannels {
		if channel.Count == 0 || channel.Count > 200 || channel.Noticeable {
			continue
		}
		if _, isPublic := publicChannelMap[channel.ChannelId]; !isPublic {
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
			Channel:          channel,
			Messages:         messages,
			PublicChannelMap: publicChannelMap,
			UserMap:          userMap,
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
	} else if resp.StatusCode != http.StatusCreated {
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
