package api

import (
	"context"
	"errors"
	"math/big"

	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/hexutil"
	"github.com/ThinkiumGroup/go-common/log"
	"github.com/ThinkiumGroup/go-thinkium/consts"
	"github.com/ThinkiumGroup/go-thinkium/models"
	"github.com/ThinkiumGroup/go-thinkium/rpcserver"
)

// PublicBlockChainAPI provides an API to access the Ethereum blockchain.
// It offers only methods that operate on public data that is freely available to anyone.
type PublicBlockChainAPI struct {
	nmanager models.NetworkManager
	dmanager models.DataManager
	engine   models.Engine
	eventer  models.Eventer
}

func NewPublicBlockChainAPI(nmanager models.NetworkManager, dmanager models.DataManager,
	engine models.Engine, eventer models.Eventer) *PublicBlockChainAPI {
	return &PublicBlockChainAPI{
		nmanager: nmanager,
		dmanager: dmanager,
		engine:   engine,
		eventer:  eventer,
	}
}

func (api *PublicBlockChainAPI) Accounts() []common.Address {
	var addrs []common.Address
	return addrs
}

func (api *PublicBlockChainAPI) BlockNumber(context.Context) hexutil.Uint64 {
	if api.dmanager.IsDataNode() || api.dmanager.IsMemoNode() {
		stats, err := api.dmanager.GetChainStats(api.dmanager.DataNodeOf())
		if err != nil {
			return hexutil.Uint64(0)
		}
		return hexutil.Uint64(stats.CurrentHeight)
	}
	return hexutil.Uint64(0)
}

func (api *PublicBlockChainAPI) Call(ctx context.Context, args TransactionArgs, blockNrOrHash BlockNumberOrHash, overrides *StateOverride) (hexutil.Bytes, error) {
	if !api.dmanager.IsDataNode() && !api.dmanager.IsMemoNode() {
		return nil, errors.New("current node is not a DATA node")
	}
	chainId := api.dmanager.DataNodeOf()
	chainData, err := api.dmanager.GetChainData(chainId)
	if err != nil {
		return nil, err
	}
	if args.To == nil {
		return nil, errors.New("illegal to address")
	}
	from := args.From
	if from == nil {
		defaultAddr := common.HexToAddress("0000000000000000000000000000000000000000")
		from = &defaultAddr
	}
	if args.Data == nil {
		return nil, errors.New("no input found")
	}
	acc, _ := chainData.GetAccount(from)
	if acc == nil {
		acc = models.NewAccount(*from, nil)
	}
	tx := &models.Transaction{
		ChainID:  chainId,
		From:     from,
		To:       args.To,
		Nonce:    acc.Nonce,
		UseLocal: false,
		Val:      big.NewInt(0),
		Input:    *args.Data,
		Version:  2,
	}
	extrakeys := &models.Extra{
		Type:     models.LegacyTxType,
		Gas:      0,
		GasPrice: big.NewInt(0),
	}
	if args.Gas != nil {
		extrakeys.Gas = uint64(*args.Gas)
	}
	if args.GasPrice != nil {
		extrakeys.GasPrice = args.GasPrice.ToInt()
	}
	tx.SetExtraKeys(extrakeys)
	// extra, _ := json.Marshal(extrakeys)
	// tx.Extra = extra
	bc := chainData.GetBlockChain()
	if bc == nil {
		return nil, errors.New(rpcserver.ErrInvalidBlockChain)
	}
	if bc.CurrentBlock() == nil {
		return nil, errors.New(rpcserver.ErrNilBlock)
	}
	rec, err := chainData.CallProcessTx(tx, nil, bc.CurrentBlock().BlockHeader)
	if err != nil {
		return nil, err
	}
	receipt := rec.(*models.Receipt)
	if receipt == nil {
		return nil, nil
	}
	return receipt.Out, nil
}

func (api *PublicBlockChainAPI) Coinbase() string {
	return ""
}

func (api *PublicBlockChainAPI) ChainId() (*hexutil.Big, error) {
	return (*hexutil.Big)(new(big.Int).SetUint64(models.ETHChainID(api.dmanager.DataNodeOf(), models.TxVersion))), nil

}

func (api *PublicBlockChainAPI) GasPrice() (*hexutil.Big, error) {
	gasprice, _ := new(big.Int).SetString(consts.GasPrice, 10)
	return (*hexutil.Big)(gasprice), nil
}

func (api *PublicBlockChainAPI) GetBalance(ctx context.Context, address common.Address, blockNrOrHash BlockNumberOrHash) (*hexutil.Big, error) {
	chainid := api.dmanager.DataNodeOf()
	cdata, err := api.dmanager.GetChainData(chainid)
	if err != nil {
		return nil, err
	}
	acc, _ := cdata.GetAccount(&address)
	if acc == nil {
		acc = models.NewAccount(address, nil)
	}
	return (*hexutil.Big)(acc.Balance), nil

}

func (api *PublicBlockChainAPI) GetProof(ctx context.Context, address common.Address, storageKeys []string, blockNrOrHash BlockNumberOrHash) (*AccountResult, error) {
	if !api.dmanager.IsDataNode() && !api.dmanager.IsMemoNode() {
		return nil, errors.New("current node is not DATA node")
	}
	chainid := api.dmanager.DataNodeOf()
	cdata, err := api.dmanager.GetChainData(chainid)
	if err != nil {
		return nil, err
	}
	acc, _ := cdata.GetAccount(&address)
	if acc == nil {
		acc = models.NewAccount(address, nil)
	}
	res := &AccountResult{
		Address:      address,
		AccountProof: nil,
		Balance:      (*hexutil.Big)(acc.Balance),
		CodeHash:     common.BytesToHash(acc.CodeHash),
		Nonce:        hexutil.Uint64(acc.Nonce),
		StorageHash:  common.BytesToHash(acc.StorageRoot),
		StorageProof: nil,
	}
	return res, nil

}

func (api *PublicBlockChainAPI) GetBlockByHash(ctx context.Context, hash common.Hash, fullTx bool) (map[string]interface{}, error) {
	if !api.dmanager.IsDataNode() && !api.dmanager.IsMemoNode() {
		return nil, errors.New("current node is not a DATA node")
	}
	cdata, err := api.dmanager.GetChainData(api.dmanager.DataNodeOf())
	if err != nil {
		return nil, err
	}
	block, err := cdata.GetBlockByHash(hash.Slice())
	if err != nil {
		return nil, err
	}
	return api.rpcMarshalBlock(ctx, block, true, fullTx)

}

func (api *PublicBlockChainAPI) GetBlockByNumber(ctx context.Context, number BlockNumber, fulltx bool) (map[string]interface{}, error) {
	var err error
	if !api.dmanager.IsDataNode() && !api.dmanager.IsMemoNode() {

		return nil, errors.New("current node is not a DATA node")
	}
	cdata, err := api.dmanager.GetChainData(api.dmanager.DataNodeOf())
	if err != nil {
		return nil, err
	}
	block := new(models.BlockEMessage)
	if number == LatestBlockNumber {
		block, err = cdata.GetBlock(cdata.GetCurrentHeight())
	} else {
		block, err = cdata.GetBlock(common.Height(number))
	}
	if err != nil || block == nil {
		return nil, err
	}
	return api.rpcMarshalBlock(ctx, block, true, fulltx)
}

func (api *PublicBlockChainAPI) rpcMarshalBlock(ctx context.Context, block *models.BlockEMessage, incLTx, fullTx bool) (map[string]interface{}, error) {
	fields := RPCMarshalHeader(block)
	if incLTx {
		formatTx := func(tx *models.Transaction) (interface{}, error) {
			return tx.Hash(), nil
		}
		if fullTx {
			formatTx = func(tx *models.Transaction) (interface{}, error) {
				return newRPCTransactionFromBlockHash(block, tx.Hash()), nil
			}
		}
		txs := block.BlockBody.Txs
		transactions := make([]interface{}, len(txs))
		var err error
		for i, tx := range txs {
			if transactions[i], err = formatTx(tx); err != nil {
				return nil, err
			}
		}
		fields["transactions"] = transactions
	}

	fields["uncles"] = make([]common.Hash, 0)
	return fields, nil
}

func RPCMarshalHeader(block *models.BlockEMessage) map[string]interface{} {
	head := block.BlockHeader
	result := map[string]interface{}{
		"number":           (*hexutil.Big)(big.NewInt(int64(head.GetHeight()))),
		"hash":             head.Hash(),
		"parentHash":       head.ParentHash,
		"nonce":            nil,
		"mixHash":          common.Hash{},
		"sha3Uncles":       nil,
		"logsBloom":        nil,
		"stateRoot":        head.StateRoot,
		"miner":            common.Address{},
		"difficulty":       (*hexutil.Big)(big.NewInt(0)),
		"extraData":        hexutil.Bytes([]byte{}),
		"size":             nil,
		"gasLimit":         30000000,
		"gasUsed":          (*hexutil.Big)(big.NewInt(0)),
		"timestamp":        hexutil.Uint64(head.TimeStamp),
		"transactionsRoot": head.TransactionRoot,
		"receiptsRoot":     head.ReceiptRoot,
	}
	return result
}

func (api *PublicBlockChainAPI) GetTransactionByBlockHashAndIndex(ctx context.Context, blockHash common.Hash, index hexutil.Uint) *RPCTransaction {
	if !api.dmanager.IsDataNode() && !api.dmanager.IsMemoNode() {
		return nil
	}
	cdata, err := api.dmanager.GetChainData(api.dmanager.DataNodeOf())
	if err != nil {
		return nil
	}
	block, err := cdata.GetBlockByHash(blockHash.Slice())
	if err != nil || block == nil || block.BlockHeader == nil || block.BlockBody == nil {
		return nil
	}
	rpctx, err := api.genRpcTxFromBlock(cdata, block, index)
	if err != nil {
		return nil
	}
	return rpctx
}

func (api *PublicBlockChainAPI) genRpcTxFromBlock(cdata models.DataHolder, block *models.BlockEMessage, index hexutil.Uint) (rpctx *RPCTransaction, err error) {
	if int(index) < 0 || int(index) >= len(block.BlockBody.Txs) {
		return
	}
	transaction := block.BlockBody.Txs[index]
	var receipt *models.Receipt
	if block.BlockHeader.ReceiptRoot != nil && !block.BlockHeader.ReceiptRoot.SliceEqual(common.NilHashSlice) {
		receiptHash := *(block.BlockHeader.ReceiptRoot)

		receipts := models.ReadReceipts(cdata.GetDb(), receiptHash)
		receipt, err = models.ReadReceipt(receipts, (int)(index))
		if err != nil {
			log.Error("[ETHRPC] GetTransactionByHash ReadReceipt error:", err.Error())
			return
		}
	}
	if receipt == nil {
		return
	}
	txi := &models.TXIndex{
		BlockHeight: uint64(block.GetHeight()),
		BlockHash:   block.Hash(),
		Index:       uint32(index),
	}
	rpctx, err = GenRpcTxRes(transaction, txi, receipt)
	return
}

func (api *PublicBlockChainAPI) GetTransactionByBlockNumberAndIndex(ctx context.Context, blockNr BlockNumber, index hexutil.Uint) *RPCTransaction {
	if !api.dmanager.IsDataNode() && !api.dmanager.IsMemoNode() {
		return nil
	}
	cdata, err := api.dmanager.GetChainData(api.dmanager.DataNodeOf())
	if err != nil {
		return nil
	}
	block := new(models.BlockEMessage)
	if blockNr == LatestBlockNumber {
		block, err = cdata.GetBlock(cdata.GetCurrentHeight())
	} else {
		block, err = cdata.GetBlock(common.Height(blockNr))
	}
	if err != nil || block == nil || block.BlockHeader == nil || block.BlockBody == nil {
		return nil
	}
	rpctx, err := api.genRpcTxFromBlock(cdata, block, index)
	if err != nil {
		return nil
	}
	return rpctx
}

func (api *PublicBlockChainAPI) GetBlockTransactionCountByHash(ctx context.Context, blockHash common.Hash) *hexutil.Uint {
	if !api.dmanager.IsDataNode() && !api.dmanager.IsMemoNode() {
		return nil
	}
	cdata, err := api.dmanager.GetChainData(api.dmanager.DataNodeOf())
	if err != nil {
		return nil
	}
	b, err := cdata.GetBlockByHash(blockHash.Slice())
	if err != nil {
		return nil
	}
	txcount := uint(len(b.BlockBody.Txs))
	return (*hexutil.Uint)(&txcount)
}

func (api *PublicBlockChainAPI) GetBlockTransactionCountByNumber(ctx context.Context, blockNr BlockNumber) *hexutil.Uint {
	if !api.dmanager.IsDataNode() && !api.dmanager.IsMemoNode() {
		return nil
	}
	var err error
	cdata, err := api.dmanager.GetChainData(api.dmanager.DataNodeOf())
	if err != nil {
		return nil
	}
	block := new(models.BlockEMessage)
	if blockNr == LatestBlockNumber {
		block, err = cdata.GetBlock(cdata.GetCurrentHeight())
	} else {
		block, err = cdata.GetBlock(common.Height(blockNr))
	}
	if err != nil {
		return nil
	}
	txcount := uint(len(block.BlockBody.Txs))
	return (*hexutil.Uint)(&txcount)
}

func (api *PublicBlockChainAPI) GetTransactionByHash(ctx context.Context, hash common.Hash) (*RPCTransaction, error) {
	if !api.dmanager.IsDataNode() && !api.dmanager.IsMemoNode() {
		return nil, errors.New("current node is not a DATA node")
	}
	chainData, err := api.dmanager.GetChainData(api.dmanager.DataNodeOf())
	if err != nil {
		return nil, err
	}
	bc := chainData.GetBlockChain()
	if bc == nil {
		return nil, errors.New("Invalid blockchain")
	}
	txI, err := bc.GetBlockTxIndexs(hash[:])
	if err != nil {
		// return nil for app client
		return nil, nil
	}
	block, err := bc.GetBlockByHash(txI.BlockHash[:])
	if err != nil {
		return nil, err
	}
	if block == nil {
		return nil, errors.New(rpcserver.ErrNilBlock)
	}
	if block.BlockHeader == nil || block.BlockBody == nil {
		return nil, errors.New(rpcserver.ErrNilBlock)
	}
	if int(txI.Index) < 0 || int(txI.Index) >= len(block.BlockBody.Txs) {
		return nil, errors.New(rpcserver.ErrNilTransaction)
	}
	transaction := block.BlockBody.Txs[txI.Index]
	var receipt *models.Receipt
	if block.BlockHeader.ReceiptRoot != nil && !block.BlockHeader.ReceiptRoot.SliceEqual(common.NilHashSlice) {
		receiptHash := *(block.BlockHeader.ReceiptRoot)

		receipts := models.ReadReceipts(chainData.GetDb(), receiptHash)
		receipt, err = models.ReadReceipt(receipts, (int)(txI.Index))
		if err != nil {
			log.Error("[ETHRPC] GetTransactionByHash ReadReceipt error:", err.Error())
			return nil, err
		}
	}
	if receipt == nil {
		return nil, errors.New(rpcserver.ErrReadReceipt)
	}
	return GenRpcTxRes(transaction, txI, receipt)

}

func (api *PublicBlockChainAPI) GetTransactionCount(ctx context.Context, address common.Address, blockNrOrHash BlockNumberOrHash) (*hexutil.Uint64, error) {
	if !api.dmanager.IsDataNode() && !api.dmanager.IsMemoNode() {
		return nil, errors.New("current node is not a DATA node")
	}
	chainId := api.dmanager.DataNodeOf()
	cdata, err := api.dmanager.GetChainData(chainId)
	if err != nil {
		return nil, err
	}
	acc, _ := cdata.GetAccount(&address)
	if acc == nil {
		acc = models.NewAccount(address, nil)
	}
	return (*hexutil.Uint64)(&acc.Nonce), nil
}

func (api *PublicBlockChainAPI) GetCode(ctx context.Context, address common.Address, blockNrOrHash BlockNumberOrHash) (hexutil.Bytes, error) {
	if !api.dmanager.IsDataNode() && !api.dmanager.IsMemoNode() {
		return nil, errors.New("current node is not a DATA node")
	}
	chainId := api.dmanager.DataNodeOf()
	cdata, err := api.dmanager.GetChainData(chainId)
	if err != nil {
		return nil, err
	}
	var code []byte
	acc, _ := cdata.GetAccount(&address)
	if acc == nil {
		acc = models.NewAccount(address, nil)
	} else {
		if acc.IsUserContract() {
			code = cdata.GetCodeByHash(common.BytesToHash(acc.CodeHash))
		}
	}
	return code, nil
}

func (api *PublicBlockChainAPI) GetLogs(ctx context.Context, query FilterQuery) ([]*models.Log, error) {
	if !api.dmanager.IsDataNode() && !api.dmanager.IsMemoNode() {
		return nil, errors.New("current node is not a DATA node")
	}
	var txLogs []*models.Log
	chainData, err := api.dmanager.GetChainData(api.dmanager.DataNodeOf())
	if err != nil {
		return nil, err
	}

	if query.BlockHash != nil {
		receipts := models.ReadReceipts(chainData.GetDb(), *query.BlockHash)
		logs := make([]*models.Log, len(receipts))
		for _, recepit := range receipts {
			txLogs = append(logs, recepit.Logs...)
		}
		txLogs = filterLogs(txLogs, nil, nil, query.Addresses, query.Topics)
	} else {
		return nil, errors.New("unsupport query params")
	}
	if txLogs == nil {
		return []*models.Log{}, nil
	}
	return txLogs, nil
}

func filterLogs(logs []*models.Log, fromBlock, toBlock *big.Int, addresses []common.Address, topics [][]common.Hash) []*models.Log {
	var ret []*models.Log
Logs:
	for _, txlog := range logs {
		if fromBlock != nil && fromBlock.Int64() >= 0 && fromBlock.Uint64() > txlog.BlockNumber {
			continue
		}
		if toBlock != nil && toBlock.Int64() >= 0 && toBlock.Uint64() < txlog.BlockNumber {
			continue
		}

		if len(addresses) > 0 && !includes(addresses, txlog.Address) {
			continue
		}
		// If the to filtered topics is greater than the amount of topics in logs, skip.
		if len(topics) > len(txlog.Topics) {
			continue Logs
		}
		for i, sub := range topics {
			match := len(sub) == 0 // empty rule set == wildcard
			for _, topic := range sub {
				if txlog.Topics[i] == topic {
					match = true
					break
				}
			}
			if !match {
				continue Logs
			}
		}
		ret = append(ret, txlog)
	}
	return ret
}

func includes(addresses []common.Address, a common.Address) bool {
	for _, addr := range addresses {
		if addr == a {
			return true
		}
	}

	return false
}

func (api *PublicBlockChainAPI) GetTransactionReceipt(ctx context.Context, hash common.Hash) (map[string]interface{}, error) {
	if !api.dmanager.IsDataNode() && !api.dmanager.IsMemoNode() {
		return nil, errors.New("current node is not a DATA node")
	}
	chainData, err := api.dmanager.GetChainData(api.dmanager.DataNodeOf())
	if err != nil {
		return nil, err
	}
	bc := chainData.GetBlockChain()
	if bc == nil {
		return nil, errors.New("Invalid blockchain")
	}
	txI, err := bc.GetBlockTxIndexs(hash[:])
	if err != nil {
		return nil, nil
	}
	block, err := bc.GetBlockByHash(txI.BlockHash[:])
	if err != nil {
		return nil, err
	}
	if block == nil {
		return nil, errors.New(rpcserver.ErrNilBlock)
	}
	if block.BlockHeader == nil || block.BlockBody == nil {
		return nil, errors.New(rpcserver.ErrNilBlock)
	}
	if int(txI.Index) < 0 || int(txI.Index) >= len(block.BlockBody.Txs) {
		return nil, errors.New(rpcserver.ErrNilTransaction)
	}
	var receipt *models.Receipt
	tx := block.BlockBody.Txs[txI.Index]
	if block.BlockHeader.ReceiptRoot != nil && !block.BlockHeader.ReceiptRoot.SliceEqual(common.NilHashSlice) {
		receiptHash := *(block.BlockHeader.ReceiptRoot)

		receipts := models.ReadReceipts(chainData.GetDb(), receiptHash)
		receipt, err = models.ReadReceipt(receipts, (int)(txI.Index))
		if err != nil {
			log.Error("[ETHRPC] GetTransactionByHash ReadReceipt error:", err.Error())
			return nil, err
		}
	}
	if receipt == nil {
		return nil, errors.New(rpcserver.ErrReadReceipt)
	}
	bh := block.Hash()
	for index := range receipt.Logs {
		receipt.Logs[index].BlockHash = &bh
	}
	gasprice, _ := chainData.GetGasSettings()
	fields := map[string]interface{}{
		"blockHash":         bh,
		"blockNumber":       hexutil.Uint64(block.GetHeight()),
		"transactionHash":   hash,
		"transactionIndex":  hexutil.Uint64(txI.Index),
		"from":              tx.From,
		"to":                tx.To,
		"gasUsed":           hexutil.Uint64(receipt.GasUsed),
		"cumulativeGasUsed": hexutil.Uint64(receipt.CumulativeGasUsed),
		"contractAddress":   nil,
		"logs":              receipt.Logs,
		"type":              hexutil.Uint(tx.Type()),
		"logsBloom":         nil,
		"effectiveGasPrice": hexutil.Uint64(gasprice.Uint64()),
		"root":              nil,
		"status":            hexutil.Uint(receipt.Status),
	}
	if receipt.Logs == nil {
		fields["logs"] = [][]*models.Log{}
	}
	// If the ContractAddress is 20 0x0 bytes, assume it is not a contract creation
	if receipt.ContractAddress != nil && *receipt.ContractAddress != (common.Address{}) {
		fields["contractAddress"] = receipt.ContractAddress
	}
	return fields, nil
}

func checkTx(tx *models.Transaction, verifySig bool, sig, pub []byte) bool {
	if tx == nil {
		return false
	}
	if tx.From == nil || len(tx.From) != common.AddressLength {
		return false
	}
	if tx.ChainID == common.MainChainID {
		if tx.To == nil || len(tx.To) == 0 || tx.To.IsSystemContract() {
			return false
		}
	}
	if verifySig {
		txhash := models.ETHSigner.HashGtkm(tx)
		if v := common.VerifyHash(txhash.Slice(), pub, sig); !v {
			return false
		}
	}
	return true
}

func (api *PublicBlockChainAPI) SendRawTransaction(ctx context.Context, input hexutil.Bytes) (common.Hash, error) {
	if !api.dmanager.IsDataNode() && !api.dmanager.IsMemoNode() {
		return common.Hash{}, errors.New("current node is not a DATA node")
	}
	// to ethtransaction type
	tx := new(models.ETHTransaction)
	if err := tx.UnmarshalBinary(input); err != nil {
		return common.Hash{}, err
	}
	sig, pub, err := models.ETHSigner.RecoverSigAndPub(tx)
	if err != nil {
		return common.Hash{}, err
	}
	gtkmtx, err := tx.ToTransaction()
	if err != nil {
		return common.Hash{}, err
	}
	if ok := checkTx(gtkmtx, true, sig, pub); !ok {
		return common.Hash{}, models.ErrInvalidSig
	}
	if err := api.eventer.PostEvent(gtkmtx, pub, sig); err != nil {
		return common.Hash{}, err
	}
	return gtkmtx.Hash(), nil
}

func (api *PublicBlockChainAPI) EstimateGas(ctx context.Context, args TransactionArgs, blockNrOrHash *BlockNumberOrHash) (hexutil.Uint64, error) {
	return hexutil.Uint64(3000000), nil
}
