package main

import (
	"context"
	"testing"
	"time"

	"xray-easy/internal/interaction"
	"xray-easy/internal/store"
)

func TestTraceApplyOperationAddsRevisionOnlyForPersistedPositiveRevision(t *testing.T) {
	app := newTestApp(t, true)
	ctx := context.Background()
	for _, test := range []struct {
		name       string
		operation  store.ApplyOperation
		wantRev    int64
		wantStored bool
	}{
		{name: "missing operation", operation: store.ApplyOperation{ID: "00000000000000000000000000000001"}},
		{name: "zero revision", operation: store.ApplyOperation{ID: "00000000000000000000000000000002", Revision: 0, State: "pending"}, wantStored: true},
		{name: "positive revision", operation: store.ApplyOperation{ID: "00000000000000000000000000000003", Revision: 7, State: "pending"}, wantRev: 7, wantStored: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			operationID := test.operation.ID
			if test.wantStored {
				now := time.Now().UTC()
				test.operation.CreatedAt, test.operation.UpdatedAt = now, now
				if err := app.server.store.CreateApplyOperation(ctx, test.operation); err != nil {
					t.Fatal(err)
				}
			}
			got := app.server.traceApplyOperation(ctx, operationID)
			if interaction.OperationID(got) != operationID {
				t.Fatalf("operation ID = %q, want %q", interaction.OperationID(got), operationID)
			}
			if interaction.StateRevision(got) != test.wantRev {
				t.Fatalf("state revision = %d, want %d", interaction.StateRevision(got), test.wantRev)
			}
		})
	}
}
