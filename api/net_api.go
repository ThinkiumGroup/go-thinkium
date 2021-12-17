package api

import (
	"fmt"

	"github.com/ThinkiumGroup/go-thinkium/models"
)

type PublicNetAPI struct {
	dmanager models.DataManager
}

func NewPublicNetAPI(dmanager models.DataManager) *PublicNetAPI {
	return &PublicNetAPI{
		dmanager: dmanager,
	}
}

func (s *PublicNetAPI) Listening() bool {
	return true
}

func (s *PublicNetAPI) Version() string {
	return fmt.Sprintf("%d", models.ETHChainID(s.dmanager.DataNodeOf(), models.TxVersion))
}
