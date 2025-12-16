package logging

import (
	"context"
	"log"
	"os"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"

	"github.com/example/sijunjung-go/internal/domain"
)

// Logger persists logs to MongoDB and prints to stdout.
type Logger struct {
	mongoCollection *mongo.Collection
	stdLogger       *log.Logger
}

// New constructs a Logger writing to MongoDB and stdout.
func New(db *mongo.Database) *Logger {
	collection := db.Collection("logs")
	return &Logger{
		mongoCollection: collection,
		stdLogger:       log.New(os.Stdout, "", log.LstdFlags|log.Lshortfile),
	}
}

func (l *Logger) log(ctx context.Context, level string, msg string) {
	if l == nil {
		return
	}
	l.stdLogger.Printf("[%s] %s", level, msg)
	if l.mongoCollection == nil {
		return
	}
	entry := bson.M{
		"level":      level,
		"message":    msg,
		"created_at": time.Now(),
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, _ = l.mongoCollection.InsertOne(ctx, entry)
}

// Info writes an informational log entry.
func (l *Logger) Info(ctx context.Context, msg string) {
	l.log(ctx, "INFO", msg)
}

// Error writes an error log entry.
func (l *Logger) Error(ctx context.Context, msg string) {
	l.log(ctx, "ERROR", msg)
}

var _ domain.AppLogger = (*Logger)(nil)
