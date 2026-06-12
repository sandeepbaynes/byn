package privsep

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServiceUserNames(t *testing.T) {
	assert.Equal(t, "_byn", DaemonUser)
	assert.Equal(t, "_byn-exec", ExecUser)
}

func TestLookupServiceUIDs_AbsentUsersNotProvisioned(t *testing.T) {
	st, err := lookupState(func(string) (int, int, error) { return 0, 0, errUserNotFound })
	require.NoError(t, err)
	assert.False(t, st.Provisioned)
}

func TestLookupServiceUIDs_PresentUsersProvisioned(t *testing.T) {
	st, err := lookupState(func(name string) (int, int, error) {
		switch name {
		case ExecUser:
			return 411, 411, nil
		case DaemonUser:
			return 410, 410, nil
		}
		return 0, 0, errUserNotFound
	})
	require.NoError(t, err)
	assert.True(t, st.Provisioned)
	assert.Equal(t, 411, st.ExecUID)
	assert.Equal(t, 411, st.ExecGID)
}

func TestLookupServiceUIDs_ExecMustDifferFromOwner(t *testing.T) {
	_, err := lookupState(func(name string) (int, int, error) {
		return currentUID(), currentUID(), nil
	})
	require.ErrorIs(t, err, ErrInvalidProvisioning)
}
