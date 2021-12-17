package api

import "github.com/ThinkiumGroup/go-thinkium/consts"

// PublicWeb3API offers helper utils
type PublicWeb3API struct{}

// ClientVersion returns the node name
func (api *PublicWeb3API) ClientVersion() string {
	return consts.Version
}
