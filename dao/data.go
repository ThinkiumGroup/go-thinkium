// Copyright 2020 Thinkium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package dao

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/db"
	"github.com/ThinkiumGroup/go-common/log"
	"github.com/ThinkiumGroup/go-thinkium/config"
	"github.com/ThinkiumGroup/go-thinkium/models"
	"github.com/stephenfire/go-rtl"
)

// Block

func SaveHeaderIndexes(dbase db.Database, header *models.BlockHeader) (hashOfHeader []byte, err error) {
	hashOfHeader, err = header.HashValue()
	if err != nil {
		return nil, err
	}
	// In order to save storage space, the header is no longer saved separately
	// buf := new(bytes.Buffer)
	// err = rtl.Encode(header, buf)
	// // data, err := rtl.Marshal(header)
	// if err != nil {
	// 	return nil, err
	// }
	// data := buf.Bytes()
	batch := dbase.NewBatch()
	// // save Hash->Header
	// headerkey := db.ToBlockHeaderKey(hashOfHeader)
	// batch.Put(headerkey, data)
	// save Height->Hash
	hashkey := db.ToBlockHashKey(header.Height)
	batch.Put(hashkey, hashOfHeader)
	// save Hash->Height
	heightkey := db.ToBlockNumberKey(hashOfHeader)
	batch.Put(heightkey, header.Height.Bytes())

	if err := dbase.Batch(batch); err != nil {
		return hashOfHeader, err
	}
	return hashOfHeader, nil
}

//
// func LoadHeader(dbase db.Database, hashOfHeader []byte) (*models.BlockHeader, error) {
// 	if hashOfHeader == nil || bytes.Compare(common.NilHashSlice, hashOfHeader) == 0 {
// 		return nil, nil
// 	}
// 	key := db.ToBlockHeaderKey(hashOfHeader)
// 	data, err := dbase.Get(key)
// 	if err != nil {
// 		return nil, err
// 	}
// 	header := new(models.BlockHeader)
// 	if err = rtl.Unmarshal(data, header); err != nil {
// 		return nil, err
// 	}
// 	return header, nil
// }

func GetBlockHash(dbase db.Database, height common.Height) ([]byte, error) {
	key := db.ToBlockHashKey(height)
	hashOfHeader, err := dbase.Get(key)
	if err != nil {
		return nil, err
	}
	return hashOfHeader, nil
}

// Returns the number of saved transaction indexes and errors
func SaveBlock(dbase db.Database, hashOfHeader []byte, block *models.BlockEMessage) (int, error) {
	key := db.ToBlockKey(hashOfHeader)
	data, err := rtl.Marshal(block)
	if err != nil {
		return 0, err
	}
	// save Hash->Block
	if err = dbase.Put(key, data); err != nil {
		return 0, common.NewDvppError("save hash->block error", err)
	}

	// Record cursors of blocks reported by child chains
	if block.BlockBody != nil && len(block.BlockBody.Hds) > 0 {
		if err := SaveBlockSummary(dbase, block.BlockBody.Hds); err != nil {
			return 0, common.NewDvppError("save reports error", err)
		}
	}

	// Writes the index of all transactions in the block to the database
	txCount, err := SaveBlockTxIndexs(dbase, block)
	if err != nil {
		return 0, common.NewDvppError("save block tx index error", err)
	}
	return txCount, nil
}

func LoadBlock(dbase db.Database, hashOfHeader []byte) (*models.BlockEMessage, error) {
	if hashOfHeader == nil || bytes.Compare(common.NilHashSlice, hashOfHeader) == 0 {
		return nil, nil
	}
	key := db.ToBlockKey(hashOfHeader)
	data, err := dbase.Get(key)
	if err != nil {
		return nil, err
	}
	block := new(models.BlockEMessage)
	if err = rtl.Unmarshal(data, block); err != nil {
		return nil, err
	}
	return block, nil
}

// Record the block height cursors of all the children chains that have been packaged and
// confirmed on the parent chain (current is the parent chain)
func SaveBlockSummary(dbase db.Database, hds []*models.BlockSummary) error {
	// Traverse the confirmed report block information, record each chain cursor, and find
	// the child chain committee information should be saved
	m := make(map[common.ChainID]*models.BlockSummary)
	cm := make(map[common.ChainID]map[common.EpochNum]*models.BlockSummary)
	for _, hd := range hds {
		if hd == nil {
			continue
		}
		cursor, exist := m[hd.ChainId]
		if !exist || cursor == nil || (cursor.Height <= hd.Height) {
			m[hd.ChainId] = hd
		}
		if hd.NextComm != nil {
			// Record the child chain committee, avoid repeated writing
			curEpoch := hd.Height.EpochNum()
			cmm, ok := cm[hd.ChainId]
			if !ok {
				cmm = make(map[common.EpochNum]*models.BlockSummary)
				cm[hd.ChainId] = cmm
			}
			cmm[curEpoch+1] = hd
		}
	}
	// convert child chain committee information into slice and write it through batch
	var epochs []*models.BlockSummary
	for _, cmm := range cm {
		for _, b := range cmm {
			epochs = append(epochs, b)
		}
	}
	_, _ = db.BatchWrite(dbase, 50, len(epochs), func(j int, w db.Writer) (ok bool, err error) {
		if err := SaveEpochCommittee(w, epochs[j].ChainId, epochs[j].Height.EpochNum()+1, epochs[j].NextComm); err != nil {
			log.Warnf("save next committee %s failed: %v", epochs[j], err)
		} else {
			if config.IsLogOn(config.DataDebugLog) {
				log.Debugf("next committee of %s saved", epochs[j])
			}
		}
		return true, nil
	})
	// queued chain summaries
	bss := make([]*models.BlockSummary, 0, len(m))
	for _, hd := range m {
		bss = append(bss, hd)
	}
	// write chain summaries
	count, err := db.BatchWrite(dbase, 100, len(bss), func(j int, w db.Writer) (ok bool, err error) {
		if bss[j] == nil {
			return false, nil
		}
		if err = saveCursor(w, db.ToChainReportCursorKey(bss[j].ChainId), bss[j].Height,
			common.CopyBytes(bss[j].BlockHash[:])); err != nil {
			return false, err
		}
		return true, nil
	})
	if err == nil {
		if config.IsLogOn(config.DataDebugLog) {
			log.Debugf("SaveBlockSummary(%s): %d saved", bss, count)
		}
	}
	return err
}

// Save transation index in the block
func SaveBlockTxIndexs(dbase db.Database, block *models.BlockEMessage) (count int, err error) {
	if block == nil || block.BlockHeader == nil {
		return
	}
	header := block.BlockHeader
	var txs []*models.Transaction
	if block.BlockBody != nil {
		txs = block.BlockBody.Txs
	}

	return db.BatchWrite(dbase, 100, len(txs), func(j int, w db.Writer) (ok bool, err error) {
		if txs[j] == nil {
			return false, nil
		}
		txIndex := models.NewTXIndex(uint64(header.Height), header.Hash(), uint32(j))
		key := db.ToBlockTXIndexKey(txs[j].Hash().Bytes())
		data, err := rtl.Marshal(txIndex)
		if err != nil {
			return false, err
		}
		// save Tx.Hash->Block.Height_Hash_Index
		// if err = bc.chaindb.Put(key, data); err != nil {
		if err = w.Put(key, data); err != nil {
			log.Error("GetBlockTxIndexs saved key err = %s", err.Error())
			return false, err
		}
		return true, nil
	})
}

func GetTxIndex(dbase db.Database, txHash []byte) (*models.TXIndex, error) {
	key := db.ToBlockTXIndexKey(txHash)

	data, err := dbase.Get(key)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, errors.New("GetTxIndex not found")
	}
	txIndex := models.NewTXIndex(uint64(0), common.NilHash, uint32(0))

	err = rtl.Unmarshal(data, txIndex)
	if err != nil {
		return nil, err
	}
	return txIndex, err
}

func saveCursor(w db.Writer, key []byte, height common.Height, hashOfBlock []byte) error {
	cursor := models.BlockCursor{
		Height: height,
		Hash:   hashOfBlock,
	}
	cursorBytes, err := rtl.Marshal(cursor)
	if err != nil {
		return err
	}
	if err = w.Put(key, cursorBytes); err != nil {
		return err
	}
	return nil
}

func loadCursor(dbase db.Database, key []byte) (height common.Height, hashOfBlock []byte, exist bool, err error) {
	data, err := dbase.Get(key)
	if err != nil {
		return 0, nil, false, err
	}
	if len(data) == 0 {
		return 0, nil, false, nil
	}
	cursor := &models.BlockCursor{}
	if err = rtl.Unmarshal(data, cursor); err != nil {
		return 0, nil, false, err
	}
	if cursor.Height.IsNil() || len(cursor.Hash) == 0 {
		return 0, nil, false, nil
	}
	return cursor.Height, cursor.Hash, true, nil
}

func SaveFirstRewardCursor(dbase db.Database, height common.Height, hashOfBlock []byte) error {
	return saveCursor(dbase, db.ToFirstRewardCursorKey(), height, hashOfBlock)
}

func LoadFirstRewardCursor(dbase db.Database) (common.Height, []byte, error) {
	height, hob, _, err := loadCursor(dbase, db.ToFirstRewardCursorKey())
	return height, hob, err
}

// Block Cursor
func SaveBlockCursor(dbase db.Database, chainID common.ChainID, height common.Height, hashOfHeader []byte) error {
	return saveCursor(dbase, db.ToCurrentHeightKey(), height, hashOfHeader)
}

func LoadBlockCursor(dbase db.Database) (common.Height, []byte, error) {
	height, hob, _, err := loadCursor(dbase, db.ToCurrentHeightKey())
	return height, hob, err
}

func CheckBlockExist(dbase db.Database, height common.Height) ([]byte, bool) {
	hashKey := db.ToBlockHashKey(height)
	hashOfHeader, err := db.GetNilError(dbase, hashKey)
	if err != nil {
		if config.IsLogOn(config.DataDebugLog) {
			log.Debugf("get hash of Height:%d error: %v", height, err)
		}
		return nil, false
	}
	exist, err := dbase.Has(db.ToBlockKey(hashOfHeader))
	if err != nil {
		if config.IsLogOn(config.DataDebugLog) {
			log.Debugf("check existence of block(Height:%d Hash:%x) error: %v", height, hashOfHeader[:5], err)
		}
		return nil, false
	}
	return hashOfHeader, exist
}

func SetCursorManually(dbase db.Database, id common.ChainID, to common.Height) error {
	hoh, exist := CheckBlockExist(dbase, to)
	if !exist {
		return fmt.Errorf("block Height:%d not found", to)
	}
	old, oldhash, err := LoadBlockCursor(dbase)
	if err != nil {
		return common.NewDvppError("load old cursor failed", err)
	}
	log.Infof("old cursor of ChainID:%d is: Height:%d Hash:%x, setting new cursor to: Height:%d Hash:%x",
		id, old, oldhash, to, hoh)
	return SaveBlockCursor(dbase, id, to, hoh)
}

// Save Chain Epoch Committee
func SaveChainCommittee(dbase db.Database, chainID common.ChainID, epochNum common.EpochNum, committee *models.Committee) error {
	commBytes, err := rtl.Marshal(committee)
	if err != nil {
		return err
	}
	if err = dbase.Put(db.ToChainCommitteeKey(chainID, epochNum), commBytes); err != nil {
		return err
	}
	return nil
}

// Get Chain Epoch Committee
func GetChainCommittee(dbase db.Database, chainID common.ChainID, epochNum common.EpochNum) (*models.Committee, error) {
	bytes, err := dbase.Get(db.ToChainCommitteeKey(chainID, epochNum))
	if err != nil {
		return nil, err
	}
	if len(bytes) == 0 {
		return nil, nil
	}
	comm := new(models.Committee)
	if err = rtl.Unmarshal(bytes, comm); err != nil {
		return nil, err
	}
	return comm, nil
}

func SaveNextCommittee(dbase db.Database, chainId common.ChainID, nextEpoch common.EpochNum, current, next *models.Committee) error {
	ec := models.NewEpochComm(next, current)
	return SaveEpochCommittee(dbase, chainId, nextEpoch, ec)
}

func SaveEpochCommittee(dbase db.Writer, chainId common.ChainID, nextEpoch common.EpochNum, ec *models.EpochCommittee) error {
	if ec.IsEmpty() {
		if config.IsLogOn(config.DataLog) {
			log.Warnf("ignoring SaveEpochCommitte(ChainID:%d, Epoch:%d, %s) which is empty", chainId, nextEpoch, ec)
		}
		return nil
	}
	if bytes, err := rtl.Marshal(ec); err != nil {
		return err
	} else {
		key := db.ToEpochCommKey(chainId, nextEpoch)
		if config.IsLogOn(config.DataDebugLog) {
			log.Debugf("SaveEpochCommittee(ChainID:%d, Epoch:%d, %s)", chainId, nextEpoch, ec)
		}
		return dbase.Put(key, bytes)
	}
}

func LoadEpochCommittee(dbase db.Database, chainId common.ChainID, epoch common.EpochNum) (*models.EpochCommittee, error) {
	bytes, err := dbase.Get(db.ToEpochCommKey(chainId, epoch))
	if err != nil {
		return nil, err
	}
	if len(bytes) == 0 {
		// to be compatible with old data
		comm, err := GetChainCommittee(dbase, chainId, epoch)
		if err != nil {
			return nil, err
		}
		if comm == nil {
			return nil, nil
		}
		return models.NewEpochComm(comm, nil), nil
	}
	ec := new(models.EpochCommittee)
	if err = rtl.Unmarshal(bytes, ec); err != nil {
		return nil, err
	}
	return ec, nil
}

// Save all cursors of children chains which have been recorded on parent(reported to) chain
// (current is one of children chains)
// chainId: current chain id
// parentId: chain id reported to
// block: block of parent chain
func SaveChainHeightHeaders(dbase db.Database, chainId common.ChainID, parentId common.ChainID, block *models.BlockEMessage) error {
	if len(block.BlockBody.Hds) == 0 {
		return nil
	}
	// Save the header of the parent chain block and the header reported by the child chain
	// packed in the block
	bpfKey := db.ToChainHeightProofKey(block.GetChainID(), block.GetHeight())
	bpf := &models.HeaderSummary{
		Header:    block.BlockHeader,
		Summaries: block.BlockBody.Hds,
	}
	bpfBytes, err := rtl.Marshal(bpf)
	if err = dbase.Put(bpfKey, bpfBytes); err != nil {
		return err
	}

	// Save the block height of each child chain packed by the parent chain and the index to
	// the parent chain block HDS information
	batch := dbase.NewBatch()
	for _, hd := range block.BlockBody.Hds {
		if hd.ChainId != chainId {
			// Only the block of current chain confirmed by the main chain is recorded
			continue
		}
		if common.PkgedBlocks.CAS(hd.ChainId, hd.Height) {
			batch.Put(db.ToChainHeightHeaderKey(hd.ChainId, hd.Height), bpfKey)
		}
	}
	if err := dbase.Batch(batch); err != nil {
		return err
	}
	return nil
}

// Gets the HDS information of the specified block confirmed by the main chain, including the
// block header of the main chain containing the block header (chainid + height) and the packed
// sub chain block header information (HDS)
func GetChainHeightHeader(dbase db.Database, chainID common.ChainID, height common.Height) (*models.HeaderSummary, error) {
	bytes, err := dbase.Get(db.ToChainHeightHeaderKey(chainID, height))
	if err != nil {
		return nil, err
	}
	if len(bytes) == 0 {
		return nil, nil
	}
	bpfBytes, err := dbase.Get(bytes)
	if err != nil {
		return nil, err
	}
	if len(bpfBytes) == 0 {
		return nil, nil
	}
	hds := new(models.HeaderSummary)
	if err = rtl.Unmarshal(bpfBytes, hds); err != nil {
		return nil, err
	}
	return hds, nil
}

// Gets the block header and sub chain block header information contained in the block specified
// by chainid+height
func GetChainHeightHeaderSummary(dbase db.Database, chainID common.ChainID, height common.Height) (*models.HeaderSummary, error) {
	bytes, err := dbase.Get(db.ToChainHeightProofKey(chainID, height))
	if err != nil {
		return nil, err
	}
	if len(bytes) == 0 {
		return nil, nil
	}
	hds := new(models.HeaderSummary)
	if err = rtl.Unmarshal(bytes, hds); err != nil {
		return nil, err
	}
	return hds, nil
}

func SaveRRTrieRoot(dbase db.Database, era common.EraNum, rootOfRRTrie []byte) error {
	return dbase.Put(db.ToRRKey(era), rootOfRRTrie)
}

func LoadRRTrieRoot(dbase db.Database, era common.EraNum) ([]byte, error) {
	return dbase.Get(db.ToRRKey(era))
}

func SaveUnverifiedBlock(dbase db.Database, height common.Height, block *models.BlockEMessage) error {
	if block == nil {
		return common.ErrNil
	}
	key := db.ToBlockNotVerified(height)
	data, err := rtl.Marshal(block)
	if err != nil {
		return err
	}
	return dbase.Put(key, data)
}

func LoadUnverifiedBlock(dbase db.Database, height common.Height) (*models.BlockEMessage, error) {
	key := db.ToBlockNotVerified(height)
	data, err := dbase.Get(key)
	if err != nil {
		return nil, err
	}
	block := new(models.BlockEMessage)
	if err = rtl.Unmarshal(data, block); err != nil {
		return nil, err
	}
	return block, nil
}

func SaveReportCursor(dbase db.Database, chainId common.ChainID, height common.Height, hashOfBlock []byte) error {
	return saveCursor(dbase, db.ToChainReportCursorKey(chainId), height, hashOfBlock)
}

func LoadReportCursor(dbase db.Database, chainId common.ChainID) (height common.Height, hashOfBlock []byte, exist bool, err error) {
	return loadCursor(dbase, db.ToChainReportCursorKey(chainId))
}

func StoreStorageEntries(dbase db.Database, root common.Hash, num int, entries []models.EntryHashHash) error {
	key := db.ToStorageEntryKey(root.Bytes(), num)
	data, err := rtl.Marshal(entries)
	if err != nil {
		return err
	}
	return dbase.Put(key, data)
}

func LoadStorageEntries(dbase db.Database, root common.Hash, num int) ([]models.EntryHashHash, error) {
	key := db.ToStorageEntryKey(root.Bytes(), num)
	data, err := dbase.Get(key)
	if err != nil {
		return nil, err
	}
	var ret []models.EntryHashHash
	if err = rtl.Unmarshal(data, &ret); err != nil {
		return nil, err
	}
	return ret, nil
}

func RemoveStorageEntries(dbase db.Database, root common.Hash, num int) error {
	key := db.ToStorageEntryKey(root.Bytes(), num)
	return dbase.Delete(key)
}
