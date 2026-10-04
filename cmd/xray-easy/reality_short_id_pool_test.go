package main

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

type reservedShortIDPoolStub struct {
	seedErr error
	listErr error
	ids     []string
	seeded  bool
	listed  bool
}

func (pool *reservedShortIDPoolStub) SeedReservedShortIDs(context.Context, int, func() (string, error)) error {
	pool.seeded = true
	return pool.seedErr
}

func (pool *reservedShortIDPoolStub) ListReservedShortIDs(context.Context) ([]string, error) {
	pool.listed = true
	return append([]string(nil), pool.ids...), pool.listErr
}

func TestLoadReservedShortIDsReportsSeedAndQueryErrors(t *testing.T) {
	seedErr := errors.New("reserve seeding failed")
	pool := &reservedShortIDPoolStub{seedErr: seedErr}
	if ids, err := loadReservedShortIDs(t.Context(), pool); !errors.Is(err, seedErr) || ids != nil || !pool.seeded || pool.listed {
		t.Fatalf("seed failure result = %v, %v; pool=%+v", ids, err, pool)
	}

	listErr := errors.New("reserve query failed")
	pool = &reservedShortIDPoolStub{listErr: listErr}
	if ids, err := loadReservedShortIDs(t.Context(), pool); !errors.Is(err, listErr) || ids != nil || !pool.seeded || !pool.listed {
		t.Fatalf("list failure result = %v, %v; pool=%+v", ids, err, pool)
	}

	pool = &reservedShortIDPoolStub{ids: []string{"first", "second"}}
	ids, err := loadReservedShortIDs(t.Context(), pool)
	if err != nil || !reflect.DeepEqual(ids, pool.ids) || !pool.seeded || !pool.listed {
		t.Fatalf("successful reserve load = %v, %v; pool=%+v", ids, err, pool)
	}
}
