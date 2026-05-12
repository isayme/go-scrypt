package scrypt

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHash(t *testing.T) {
	require := require.New(t)

	t.Run("hash with default params", func(t *testing.T) {
		hashed, err := Hash("123456", DefaultParams)
		require.Nil(err)

		ok, err := Verify("123456", hashed)
		require.Nil(err)
		require.True(ok)

		require.True(strings.Contains(hashed, fmt.Sprintf("r=%d", DefaultParams.R)))
		require.True(strings.Contains(hashed, fmt.Sprintf("n=%d", DefaultParams.N)))
		require.True(strings.Contains(hashed, fmt.Sprintf("p=%d", DefaultParams.P)))
	})
}

func TestVerify(t *testing.T) {
	require := require.New(t)

	t.Run("verify", func(t *testing.T) {
		testCases := []struct {
			password string
			hashed   string
		}{
			{
				password: "123",
				hashed:   "$scrypt$n=16384,r=8,p=1$WAQ74Fsr6DjVztxcFc0Kjw==$tVLlmbQ8lYtI6/VHPccl39BGaj4asiqB6W+KEK+s0DE=",
			},
			{
				password: "123456",
				hashed:   "$scrypt$n=8192,r=9,p=2$b+Ng+u8n9ubxtP5kLJLI5w==$3KmxQ4ZsDLQnH6iFD1iNrnrswfnG7ExHTAuN1+4m1AU=",
			},
		}

		for _, tc := range testCases {
			ok, err := Verify(tc.password, tc.hashed)
			require.Nil(err)
			require.True(ok)
		}
	})

	t.Run("error", func(t *testing.T) {
		valid, err := Verify("123", "base hased")
		require.NotNil(err)
		require.False(valid)
	})
}

func TestParseHashed(t *testing.T) {
	require := require.New(t)

	t.Run("parse salt", func(t *testing.T) {
		for i := 0; i < 10; i++ {
			expectSalt, err := randomBytes(4)
			require.Nil(err)

			expectKey, err := randomBytes(5)
			require.Nil(err)

			hashed := fmt.Sprintf("$scrypt$n=16384,r=8,p=1$%s$%s", base64.StdEncoding.EncodeToString(expectSalt), base64.StdEncoding.EncodeToString(expectKey))
			key, salt, _, err := parseHashed(hashed)
			require.Nil(err)
			require.Equal(expectSalt, salt)
			require.Equal(expectKey, key)
		}
	})

	t.Run("parse params", func(t *testing.T) {
		testCases := []struct {
			hashed string
			params Params
		}{
			{
				hashed: "$scrypt$n=16384,r=8,p=1$WAQ74Fsr6DjVztxcFc0Kjw==$tVLlmbQ8lYtI6/VHPccl39BGaj4asiqB6W+KEK+s0DE=",
				params: Params{
					N:      16384,
					R:      8,
					P:      1,
					KeyLen: 32,
				},
			},
			{
				hashed: "$scrypt$r=8,p=1,n=16384$WAQ74Fsr6DjVztxcFc0Kjw==$tVLlmbQ8lYtI6/VHPccl39BGaj4asiqB6W+KEK+s0DE=",
				params: Params{
					N:      16384,
					R:      8,
					P:      1,
					KeyLen: 32,
				},
			},
			{
				hashed: "$scrypt$n=16385,r=9,p=2$WAQ74Fsr6DjVztxcFc0Kjw==$tVLlmbQ8lYtI6/VHPccl39BGaj4asiqB6W+KEK+s0DE=",
				params: Params{
					N:      16385,
					R:      9,
					P:      2,
					KeyLen: 32,
				},
			},
		}

		for _, tc := range testCases {
			_, _, params, err := parseHashed(tc.hashed)
			require.Nil(err)
			require.Equal(tc.params.KeyLen, params.KeyLen)
			require.Equal(tc.params.N, params.N)
			require.Equal(tc.params.P, params.P)
			require.Equal(tc.params.R, params.R)
		}
	})

	t.Run("bad cases", func(t *testing.T) {
		testCases := []string{
			"$scrypt1$n=16385,r=9,p=2$WAQ74Fsr6DjVztxcFc0Kjw==$tVLlmbQ8lYtI6/VHPccl39BGaj4asiqB6W+KEK+s0DE=",
			"$scrypt$n-16385,r=9,p=2$WAQ74Fsr6DjVztxcFc0Kjw==$tVLlmbQ8lYtI6/VHPccl39BGaj4asiqB6W+KEK+s0DE=",
			"$scrypt$n=16385,r=9,p=2$WAQ74Fsr6DjVztxcFc0Kjw$tVLlmbQ8lYtI6/VHPccl39BGaj4asiqB6W+KEK+s0DE=",
			"$scrypt$n=16385,r=a,p=2$WAQ74Fsr6DjVztxcFc0Kjw$tVLlmbQ8lYtI6/VHPccl39BGaj4asiqB6W+KEK+s0DE=",
			"$scrypt$n=16385,r=9,p=2$WAQ74Fsr6DjVztxcFc0Kjw==$tVLlmbQ8lYtI6/VHPccl39BGaj4asiqB6W+KEKE",
		}

		for _, tc := range testCases {
			_, _, _, err := parseHashed(tc)
			require.NotNil(err)
		}
	})
}
