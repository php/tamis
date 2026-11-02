package skill

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPack(t *testing.T) {
	text, err := Pack("php-src")
	require.NoError(t, err)
	assert.Contains(t, text, "## php-src classification")

	for _, name := range []string{"", "unknown", "../SKILL", "php-src.md"} {
		_, err := Pack(name)
		assert.EqualError(t, err, `unknown pack "`+name+`"`)
	}
}
