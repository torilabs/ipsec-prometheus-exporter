package strongswan

import (
	"context"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
)

func TestCollector_Check(t *testing.T) {
	tests := []struct {
		name          string
		viciClientErr error
		wantErr       bool
		wantCloseCall int
	}{
		{
			name:          "Healthy result",
			viciClientErr: nil,
			wantErr:       false,
			wantCloseCall: 1,
		},
		{
			name:          "Unhealthy result",
			viciClientErr: errors.New("some error"),
			wantErr:       true,
			wantCloseCall: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			viciClientFnCalls := 0
			fvc := &fakeViciClient{}
			c := NewCollector(func() (ViciClient, error) {
				viciClientFnCalls++
				return fvc, tt.viciClientErr
			})
			if err := c.Check(context.TODO()); (err != nil) != tt.wantErr {
				t.Errorf("Check() error = %v, wantErr %v", err, tt.wantErr)
			}
			require.Equal(t, 1, viciClientFnCalls, "number of vici client function calls")
			require.Equal(t, tt.wantCloseCall, fvc.closeTriggered, "number of vici client close function calls")
		})
	}
}
