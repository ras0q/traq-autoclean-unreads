package config

import (
	"context"
	"os"

	"github.com/traPtitech/go-traq"
)

var (
	traqBotAccessToken = os.Getenv("TRAQ_BOT_ACCESS_TOKEN")
)

func CtxWithAccessToken(ctx context.Context) context.Context {
	return context.WithValue(ctx, traq.ContextAccessToken, traqBotAccessToken)
}
