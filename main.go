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

	"github.com/gorilla/sessions"
	"github.com/ras0q/traq-autoclean-unreads/internal/cleaner"
	"github.com/ras0q/traq-autoclean-unreads/internal/handler"
	"github.com/traPtitech/go-traq"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/oauth2"
)

func main() {
	// Register oauth2.Token to gob for session
	gob.Register(&oauth2.Token{})

	// slog.SetLogLoggerLevel(slog.LevelDebug)

	dbName := os.Getenv("MONGODB_DATABASE")
	mongoClient, err := mongo.Connect(context.Background(),
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
	defer func() {
		if err := mongoClient.Disconnect(context.Background()); err != nil {
			panic(err)
		}
	}()

	db := mongoClient.Database(dbName)
	apiClient := traq.NewAPIClient(traq.NewConfiguration())

	c := cleaner.Cleaner{
		DB:        db,
		APIClient: apiClient,
	}

	go c.Run()

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

	const addr = ":8080"
	slog.Info("Server starting...", "addr", addr)
	panic(http.ListenAndServe(addr, nil)) // TODO: graceful shutdown
}
