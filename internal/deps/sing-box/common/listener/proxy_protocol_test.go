package listener

import (
	"errors"
	"net"
	"testing"

	proxyproto "github.com/pires/go-proxyproto"
	"github.com/stretchr/testify/require"
)

func TestProxyProtocolPolicyRequiresHeaderFromTrustedPeer(t *testing.T) {
	policy, err := newProxyProtocolPolicy([]string{"203.0.113.10", "2001:db8::/32"}, false)
	require.NoError(t, err)

	result, err := policy(&net.TCPAddr{IP: net.ParseIP("203.0.113.10"), Port: 12345})
	require.NoError(t, err)
	require.Equal(t, proxyproto.REQUIRE, result)

	result, err = policy(&net.TCPAddr{IP: net.ParseIP("2001:db8::42"), Port: 12345})
	require.NoError(t, err)
	require.Equal(t, proxyproto.REQUIRE, result)
}

func TestProxyProtocolPolicyCanAllowHeaderlessTrustedPeer(t *testing.T) {
	policy, err := newProxyProtocolPolicy([]string{"10.0.0.0/8"}, true)
	require.NoError(t, err)

	result, err := policy(&net.TCPAddr{IP: net.ParseIP("10.20.30.40"), Port: 12345})
	require.NoError(t, err)
	require.Equal(t, proxyproto.USE, result)
}

func TestProxyProtocolPolicyRejectsUntrustedPeer(t *testing.T) {
	policy, err := newProxyProtocolPolicy([]string{"10.0.0.0/8"}, false)
	require.NoError(t, err)

	result, err := policy(&net.TCPAddr{IP: net.ParseIP("198.51.100.7"), Port: 12345})
	require.Equal(t, proxyproto.REJECT, result)
	require.True(t, errors.Is(err, proxyproto.ErrInvalidUpstream))
}

func TestProxyProtocolPolicyRejectsInvalidConfiguration(t *testing.T) {
	_, err := newProxyProtocolPolicy(nil, false)
	require.Error(t, err)

	_, err = newProxyProtocolPolicy([]string{"not-an-ip"}, false)
	require.Error(t, err)
}
