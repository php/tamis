package skill

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPacks(t *testing.T) {
	text, err := Packs([]string{"php-src", "php-src"})
	require.NoError(t, err)
	assert.Equal(t, 1, strings.Count(text, "## php-src classification"), "a pack named twice should be added once")

	text, err = Packs(nil)
	require.NoError(t, err)
	assert.Empty(t, text)

	for _, name := range []string{"", "unknown", "../SKILL", "php-src.md"} {
		_, err := Packs([]string{"php-src", name})
		assert.EqualError(t, err, `unknown pack "`+name+`"`)
	}
}
