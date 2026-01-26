package mongo

import (
	"context"
	"errors"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"

	"github.com/example/sijunjung-go/internal/domain"
	"github.com/example/sijunjung-go/internal/model"
)

// UserRepository implements domain.UserRepository with MongoDB.
type UserRepository struct {
	collection *mongo.Collection
}

// NewUserRepository builds a user repository backed by MongoDB.
func NewUserRepository(db *mongo.Database) *UserRepository {
	return &UserRepository{collection: db.Collection("users")}
}

// Create inserts a new user document.
func (r *UserRepository) Create(ctx context.Context, user *model.User) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	_, err := r.collection.InsertOne(ctx, user)
	if mongo.IsDuplicateKeyError(err) {
		return errors.New("user with this email already exists")
	}
	return err
}

// FindByEmail returns a user by email.
func (r *UserRepository) FindByEmail(ctx context.Context, email string) (*model.User, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	var user model.User
	if err := r.collection.FindOne(ctx, bson.M{"email": email}).Decode(&user); err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, errors.New("user not found")
		}
		return nil, err
	}
	return &user, nil
}

// UpdatePassword updates the password hash for a user.
func (r *UserRepository) UpdatePassword(ctx context.Context, email, passwordHash string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	result, err := r.collection.UpdateOne(ctx, bson.M{"email": email}, bson.M{"$set": bson.M{"password_hash": passwordHash}})
	if err != nil {
		return err
	}
	if result.MatchedCount == 0 {
		return errors.New("user not found")
	}
	return nil
}

// FindByID returns a user by ID.
func (r *UserRepository) FindByID(ctx context.Context, id string) (*model.User, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	objectID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return nil, errors.New("invalid user ID")
	}

	var user model.User
	if err := r.collection.FindOne(ctx, bson.M{"_id": objectID}).Decode(&user); err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, errors.New("user not found")
		}
		return nil, err
	}
	return &user, nil
}

// Delete removes a user by ID.
func (r *UserRepository) Delete(ctx context.Context, id string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	objectID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return errors.New("invalid user ID")
	}

	result, err := r.collection.DeleteOne(ctx, bson.M{"_id": objectID})
	if err != nil {
		return err
	}
	if result.DeletedCount == 0 {
		return errors.New("user not found")
	}
	return nil
}

var _ domain.UserRepository = (*UserRepository)(nil)
