package mongo

import (
	"context"
	"errors"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"

	"github.com/example/sijunjung-go/internal/domain"
	"github.com/example/sijunjung-go/internal/model"
)

// TokenRepository implements domain.TokenRepository using MongoDB.
type TokenRepository struct {
	collection *mongo.Collection
}

// NewTokenRepository builds a token repository backed by MongoDB.
func NewTokenRepository(db *mongo.Database) *TokenRepository {
	return &TokenRepository{collection: db.Collection("tokens")}
}

// Save stores a new token document.
func (r *TokenRepository) Save(ctx context.Context, token model.Token) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, err := r.collection.InsertOne(ctx, token)
	return err
}

// Delete removes a token by value.
func (r *TokenRepository) Delete(ctx context.Context, token string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, err := r.collection.DeleteOne(ctx, bson.M{"token": token})
	return err
}

// DeleteByUserID removes all tokens for a user.
func (r *TokenRepository) DeleteByUserID(ctx context.Context, userID string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, err := r.collection.DeleteMany(ctx, bson.M{"user_id": userID})
	return err
}

// IsValid verifies the token is stored and unexpired.
func (r *TokenRepository) IsValid(ctx context.Context, token string) (bool, string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	var doc model.Token
	err := r.collection.FindOne(ctx, bson.M{"token": token}).Decode(&doc)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return false, "", nil
		}
		return false, "", err
	}
	if time.Now().After(doc.ExpiresAt) {
		_, _ = r.collection.DeleteOne(ctx, bson.M{"token": token})
		return false, "", nil
	}
	return true, doc.UserID, nil
}

var _ domain.TokenRepository = (*TokenRepository)(nil)
