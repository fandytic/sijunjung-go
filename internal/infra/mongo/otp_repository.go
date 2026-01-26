package mongo

import (
	"context"
	"errors"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/example/sijunjung-go/internal/domain"
	"github.com/example/sijunjung-go/internal/model"
)

// OTPRepository implements domain.OTPRepository with MongoDB.
type OTPRepository struct {
	collection *mongo.Collection
}

// NewOTPRepository builds an OTP repository backed by MongoDB.
func NewOTPRepository(db *mongo.Database) *OTPRepository {
	return &OTPRepository{collection: db.Collection("otps")}
}

// Save inserts or updates an OTP document for the given email.
func (r *OTPRepository) Save(ctx context.Context, otp *model.OTP) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	filter := bson.M{"email": otp.Email}
	update := bson.M{
		"$set": bson.M{
			"user_id":    otp.UserID,
			"email":      otp.Email,
			"code":       otp.Code,
			"expires_at": otp.ExpiresAt,
			"verified":   otp.Verified,
			"created_at": otp.CreatedAt,
		},
	}
	opts := options.Update().SetUpsert(true)

	_, err := r.collection.UpdateOne(ctx, filter, update, opts)
	return err
}

// FindByEmail returns an OTP by email.
func (r *OTPRepository) FindByEmail(ctx context.Context, email string) (*model.OTP, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	var otp model.OTP
	if err := r.collection.FindOne(ctx, bson.M{"email": email}).Decode(&otp); err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, errors.New("otp not found")
		}
		return nil, err
	}
	return &otp, nil
}

// MarkVerified marks an OTP as verified.
func (r *OTPRepository) MarkVerified(ctx context.Context, email string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	_, err := r.collection.UpdateOne(ctx, bson.M{"email": email}, bson.M{"$set": bson.M{"verified": true}})
	return err
}

// Delete removes an OTP document.
func (r *OTPRepository) Delete(ctx context.Context, email string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	_, err := r.collection.DeleteOne(ctx, bson.M{"email": email})
	return err
}

// DeleteByUserID removes all OTP documents for a user.
func (r *OTPRepository) DeleteByUserID(ctx context.Context, userID string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	_, err := r.collection.DeleteMany(ctx, bson.M{"user_id": userID})
	return err
}

var _ domain.OTPRepository = (*OTPRepository)(nil)
