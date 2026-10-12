package store

import (
	"context"
	"database/sql"
	"errors"

	"gorm.io/gorm"
)

// gormTx keeps the existing parameterized SQL needed by a few SQLite-specific
// atomic transitions while routing statement execution and transaction
// lifetime through GORM.
type gormTx struct {
	db *gorm.DB
}

type gormExecResult struct {
	rowsAffected int64
}

func (r gormExecResult) LastInsertId() (int64, error) {
	return 0, errors.New("last insert ID is unavailable for GORM raw execution")
}
func (r gormExecResult) RowsAffected() (int64, error) { return r.rowsAffected, nil }

func beginGormTx(ctx context.Context, db *gorm.DB) (*gormTx, error) {
	tx := db.WithContext(ctx).Begin()
	if tx.Error != nil {
		return nil, tx.Error
	}
	return &gormTx{db: tx}, nil
}

func (tx *gormTx) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	result := tx.db.WithContext(ctx).Exec(query, args...)
	if result.Error != nil {
		return nil, result.Error
	}
	return gormExecResult{rowsAffected: result.RowsAffected}, nil
}

func (tx *gormTx) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	return tx.db.WithContext(ctx).Raw(query, args...).Rows()
}

func (tx *gormTx) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	return tx.db.WithContext(ctx).Raw(query, args...).Row()
}

func (tx *gormTx) Exec(query string, args ...any) (sql.Result, error) {
	return tx.ExecContext(context.Background(), query, args...)
}

func (tx *gormTx) Query(query string, args ...any) (*sql.Rows, error) {
	return tx.QueryContext(context.Background(), query, args...)
}

func (tx *gormTx) QueryRow(query string, args ...any) *sql.Row {
	return tx.QueryRowContext(context.Background(), query, args...)
}

func (tx *gormTx) Commit() error   { return tx.db.Commit().Error }
func (tx *gormTx) Rollback() error { return tx.db.Rollback().Error }

type sqlTransaction interface {
	Exec(string, ...any) (sql.Result, error)
	Query(string, ...any) (*sql.Rows, error)
	QueryRow(string, ...any) *sql.Row
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
	Commit() error
	Rollback() error
}
