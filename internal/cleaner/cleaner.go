package cleaner

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/ras0q/traq-autoclean-unreads/internal/config"
	"github.com/ras0q/traq-autoclean-unreads/internal/filter"
	"github.com/ras0q/traq-autoclean-unreads/internal/handler"
	"github.com/ras0q/traq-autoclean-unreads/internal/repository"
	"github.com/traPtitech/go-traq"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/oauth2"
	"golang.org/x/sync/errgroup"
)

type Cleaner struct {
	DB        *mongo.Database
	APIClient *traq.APIClient
}

func (c *Cleaner) Run() {
	ticker := time.NewTicker(time.Minute) // TODO: use WebSocket
	for {
		t := <-ticker.C
		slog.Debug("tick start", "time", t)
		if err := c.Clean(context.Background()); err != nil {
			slog.Error("clean", "err", err)
		}
	}
}

func (c *Cleaner) Clean(ctx context.Context) error {
	collection := c.DB.Collection("tokens")
	cursor, err := collection.Find(ctx, bson.D{})
	if err != nil {
		return fmt.Errorf("find tokens: %w", err)
	}

	var tokens []repository.TokenSchema
	if err := cursor.All(ctx, &tokens); err != nil {
		return fmt.Errorf("iterate cursor: %w", err)
	}

	if len(tokens) == 0 {
		slog.Debug("no tokens")
		return nil
	}

	collection = c.DB.Collection("settings")
	cursor, err = collection.Find(ctx, bson.D{})
	if err != nil {
		return fmt.Errorf("find tokens: %w", err)
	}

	var settings []repository.SettingSchema
	if err := cursor.All(ctx, &settings); err != nil {
		return fmt.Errorf("iterate cursor: %w", err)
	}

	settingMap := make(map[string]repository.SettingSchema, len(settings))
	for _, setting := range settings {
		settingMap[setting.ID.String()] = setting
	}

	ctx = config.CtxWithAccessToken(ctx)
	users, resp, err := c.APIClient.UserApi.GetUsers(ctx).IncludeSuspended(true).Execute()
	if err != nil {
		return fmt.Errorf("get users: %w", err)
	} else if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("get users: invalid status (%d %s)", resp.StatusCode, resp.Status)
	}

	userMap := make(map[string]traq.User, len(users))
	for _, user := range users {
		userMap[user.Id] = user
	}

	channels, resp, err := c.APIClient.ChannelApi.GetChannels(ctx).Execute()
	if err != nil {
		return fmt.Errorf("get channels: %w", err)
	} else if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("get channels: invalid status (%d %s)", resp.StatusCode, resp.Status)
	}

	publicChannelMap := make(map[string]traq.Channel, len(users))
	for _, channel := range channels.Public {
		publicChannelMap[channel.Id] = channel
	}

	var eg errgroup.Group
	for _, token := range tokens {
		celFilter := filter.DefaultCELFilter
		setting, ok := settingMap[token.ID.String()]
		if ok && len(setting.Filter) > 0 {
			celFilter = setting.Filter
		}

		eg.Go(func() error {
			return c.cleanUnreadMessages(token, userMap, publicChannelMap, celFilter)
		})
	}

	if err := eg.Wait(); err != nil {
		return fmt.Errorf("clean unread messages: %w", err)
	}

	return nil
}

func (c *Cleaner) cleanUnreadMessages(token repository.TokenSchema, userMap map[string]traq.User, publicChannelMap map[string]traq.Channel, celFilter string) error {
	deleteToken := func() error {
		ctx := context.Background()
		collection := c.DB.Collection("tokens")
		filter := bson.D{{Key: "_id", Value: token.ID}}
		if _, err := collection.DeleteOne(ctx, filter); err != nil {
			return fmt.Errorf("delete token collection: %w", err)
		}

		ctx = config.CtxWithAccessToken(ctx)
		_, resp, err := c.APIClient.MessageApi.PostDirectMessage(ctx, token.ID.String()).
			PostMessageRequest(traq.PostMessageRequest{
				Content: "autoclean-unreadsでアクセストークンが失効したかエラーが発生したため古いアクセストークンを削除しました。" +
					"意図しないエラーの場合は再度認可を行ってください。",
			}).
			Execute()
		if err != nil {
			return fmt.Errorf("post DM: %w", err)
		}
		if resp.StatusCode != http.StatusCreated {
			return fmt.Errorf("post DM: invalid status (%d %s)", resp.StatusCode, resp.Status)
		}

		return nil
	}

	ctx := context.Background()
	tokenSource := handler.OAuth2Config.TokenSource(ctx, &oauth2.Token{
		AccessToken:  token.AccessToken,
		TokenType:    token.TokenType,
		RefreshToken: token.RefreshToken,
		Expiry:       token.Expiry,
	})
	ctx = context.WithValue(ctx, traq.ContextOAuth2, tokenSource)

	myUnreadChannels, resp, err := c.APIClient.MeApi.GetMyUnreadChannels(ctx).Execute()
	if err != nil {
		if err := deleteToken(); err != nil {
			return fmt.Errorf("delete token: %w", err)
		}
		return fmt.Errorf("get my unread channels: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		if err := deleteToken(); err != nil {
			return fmt.Errorf("delete token: %w", err)
		}
		return fmt.Errorf("get my unread channels: invalid status (%d %s)", resp.StatusCode, resp.Status)
	}

	cleanableChannelIDs := make([]string, 0, len(myUnreadChannels))
	for _, channel := range myUnreadChannels {
		if channel.Count == 0 || channel.Count > 200 || channel.Noticeable {
			continue
		}
		if _, isPublic := publicChannelMap[channel.ChannelId]; !isPublic {
			continue
		}

		messages, resp, err := c.APIClient.ChannelApi.GetMessages(ctx, channel.ChannelId).Limit(channel.Count).Since(channel.Since).Inclusive(true).Execute()
		if err != nil {
			return fmt.Errorf("get my unread messages: %w", err)
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("get my unread messages: invalid status (%d %s)", resp.StatusCode, resp.Status)
		}

		canCleanMessages, err := filter.EvaluateCEL(ctx, celFilter, filter.CELInput{
			Channel:          channel,
			Messages:         messages,
			PublicChannelMap: publicChannelMap,
			UserMap:          userMap,
		})
		if err != nil {
			return fmt.Errorf("evaluate CEL: %w", err)
		}
		if !canCleanMessages {
			continue
		}

		cleanableChannelIDs = append(cleanableChannelIDs, channel.ChannelId)
	}

	for _, channelID := range cleanableChannelIDs {
		resp, err = c.APIClient.MeApi.ReadChannel(ctx, channelID).Execute()
		if err != nil {
			return fmt.Errorf("clean unread messages: %w", err)
		}
		if resp.StatusCode != http.StatusNoContent {
			return fmt.Errorf("clean unread messages: invalid status (%d %s)", resp.StatusCode, resp.Status)
		}
	}

	return nil
}

func (c *Cleaner) notifyFromBot(userID string, content string) {
	ctx := config.CtxWithAccessToken(context.Background())
	_, resp, err := c.APIClient.MessageApi.PostDirectMessage(ctx, userID).
		PostMessageRequest(traq.PostMessageRequest{Content: content}).
		Execute()
	if err != nil {
		slog.ErrorContext(ctx, "post bot message", "err", err)
	} else if resp.StatusCode != http.StatusCreated {
		slog.ErrorContext(ctx, "post bot message", "status", resp.Status, "statusCode", resp.StatusCode)
	}
}
