package shepherd_openstack

import (
	"testing"

	"gotest.tools/assert"
)

func TestIpPoolRange(t *testing.T) {
	// single pool
	n, err := getIpCountFromPools("10.10.10.1-10.10.10.20")
	assert.NilError(t, err)
	assert.Equal(t, uint64(20), n)
	// several pools
	n, err = getIpCountFromPools("10.10.10.1-10.10.10.20,10.10.10.30-10.10.10.40")
	assert.NilError(t, err)
	assert.Equal(t, uint64(31), n)
	// ipv6 pool
	n, err = getIpCountFromPools("2a01:598:4:4011::2-2a01:598:4:4011:ffff:ffff:ffff:ffff")
	assert.NilError(t, err)
	assert.Equal(t, uint64(18446744073709551614), n)
	// empty pool
	n, err = getIpCountFromPools("")
	assert.ErrorContains(t, err, "invalid ip pool format")
	assert.Equal(t, uint64(0), n)
	// invalid pool
	n, err = getIpCountFromPools("invalid pool")
	assert.ErrorContains(t, err, "invalid ip pool format")
	assert.Equal(t, uint64(0), n)
	n, err = getIpCountFromPools("invalid-pool")
	assert.ErrorContains(t, err, "Could not parse ip pool limits")
	assert.Equal(t, uint64(0), n)
}
