package repository

import (
	"time"

	"github.com/google/uuid"
)

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
