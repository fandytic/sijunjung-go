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
	if _, err := l.mongoCollection.InsertOne(ctx, entry); err != nil {
		l.stdLogger.Printf("[WARN] Failed to persist log to MongoDB: %v", err)
	}
}

// Info writes an informational log entry.
func (l *Logger) Info(ctx context.Context, msg string) {
	l.log(ctx, "INFO", msg)
}

// Error writes an error log entry.
func (l *Logger) Error(ctx context.Context, msg string) {
	l.log(ctx, "ERROR", msg)
}

// DeleteOlderThan removes log entries older than the specified number of days.
func (l *Logger) DeleteOlderThan(ctx context.Context, days int) (int64, error) {
	if l == nil || l.mongoCollection == nil {
		return 0, nil
	}
	cutoff := time.Now().AddDate(0, 0, -days)
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	result, err := l.mongoCollection.DeleteMany(ctx, bson.M{
		"created_at": bson.M{"$lt": cutoff},
	})
	if err != nil {
		return 0, err
	}
	return result.DeletedCount, nil
}

// StartCleanup runs a background goroutine that periodically deletes old log entries.
// If retentionDays <= 0, cleanup is disabled and logs are retained forever.
func (l *Logger) StartCleanup(interval time.Duration, retentionDays int) {
	if retentionDays <= 0 {
		l.stdLogger.Printf("[INFO] Log cleanup disabled (LOG_RETENTION_DAYS=%d)", retentionDays)
		return
	}

	l.runCleanup(retentionDays)

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			l.runCleanup(retentionDays)
		}
	}()
}

func (l *Logger) runCleanup(retentionDays int) {
	deleted, err := l.DeleteOlderThan(context.Background(), retentionDays)
	if err != nil {
		l.stdLogger.Printf("[WARN] Log cleanup failed: %v", err)
		return
	}
	if deleted > 0 {
		l.stdLogger.Printf("[INFO] Log cleanup: deleted %d entries older than %d days", deleted, retentionDays)
	}
}

var _ domain.AppLogger = (*Logger)(nil)
