package rpc

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"encoding/hex"
	"errors"
	"log"
	"fmt"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto/sha3"
	"github.com/ethereum/go-ethereum/rlp"
	//"github.com/ethereum/go-ethereum/core/types"

	"github.com/sammy007/open-ethereum-pool/util"
)

var bigWordNibbles int

type RPCClient struct {
	sync.RWMutex
	Url         string
	Name        string
	sick        bool
	sickRate    int
	successRate int
	client      *http.Client
}

type GetBlockReply struct {
	Number       string   `json:"number"`
	Hash         string   `json:"hash"`
	Nonce        string   `json:"nonce"`
	Miner        string   `json:"miner"`
	Difficulty   string   `json:"difficulty"`
	GasLimit     string   `json:"gasLimit"`
	GasUsed      string   `json:"gasUsed"`
	Transactions []Tx     `json:"transactions"`
	Uncles       []string `json:"uncles"`
	// https://github.com/ethereum/EIPs/issues/95
	SealFields []string `json:"sealFields"`
}

type BlockNonce [8]byte
// MarshalText encodes n as a hex string with 0x prefix.
func (n BlockNonce) MarshalText() ([]byte, error) {
log.Printf("MarshalText ^^^^^^^")
	return hexutil.Bytes(n[:]).MarshalText()
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (n *BlockNonce) UnmarshalText(input []byte) error {
	return hexutil.UnmarshalFixedText("BlockNonce", input, n[:])
}

func (n *BlockNonce) String() string {
	return "0x" + hex.EncodeToString(n[:])
}

const (
	// BloomByteLength represents the number of bytes used in a header log bloom.
	BloomByteLength = 256

	// BloomBitLength represents the number of bits used in a header log bloom.
	BloomBitLength = 8 * BloomByteLength
)
type BloomType [BloomByteLength]byte
// MarshalText encodes b as a hex string with 0x prefix.
func (b BloomType) MarshalText() ([]byte, error) {
	return hexutil.Bytes(b[:]).MarshalText()
}

// UnmarshalText b as a hex string with 0x prefix.
func (b *BloomType) UnmarshalText(input []byte) error {
	return hexutil.UnmarshalFixedText("Bloom", input, b[:])
}

func (b *BloomType) String() string {
	return "0x" + hex.EncodeToString(b[:])
}

type Big big.Int
const badNibble = ^uint64(0)

func EncodeBig(bigint *big.Int) string {
	nbits := bigint.BitLen()
	if nbits == 0 {
		return "0x0"
	}
	return fmt.Sprintf("%#x", bigint)
}

func (b Big) MarshalText() ([]byte, error) {
	log.Printf("^^^^^^^")
	tmpStr := EncodeBig((*big.Int)(&b))
	ret := []byte(tmpStr)
	log.Printf("^^^^^^^ MarshalText : " + tmpStr + "  result len: ", len(ret))
	return ret, nil
}

func decodeNibble(in byte) uint64 {
	switch {
	case in >= '0' && in <= '9':
		return uint64(in - '0')
	case in >= 'A' && in <= 'F':
		return uint64(in - 'A' + 10)
	case in >= 'a' && in <= 'f':
		return uint64(in - 'a' + 10)
	default:
		return ^uint64(0)
	}
}

func bytesHave0xPrefix(input []byte) bool {
	return len(input) >= 2 && input[0] == '0' && (input[1] == 'x' || input[1] == 'X')
}
func checkNumberText(input []byte) (raw []byte, err error) {
	if len(input) == 0 {
		return nil, nil // empty strings are allowed
	}
	if !bytesHave0xPrefix(input) {
		return nil, hexutil.ErrMissingPrefix
	}
	input = input[2:]
	if len(input) == 0 {
		return nil, hexutil.ErrEmptyNumber
	}
	if len(input) > 1 && input[0] == '0' {
		return nil, hexutil.ErrLeadingZero
	}
	return input, nil
}
// UnmarshalJSON implements json.Unmarshaler.
func (b *Big) UnmarshalText(input []byte) error {
	raw, err := checkNumberText(input)
	if err != nil {
		return err
	}
	if len(raw) > 64 {
		return hexutil.ErrBig256Range
	}
	words := make([]big.Word, len(raw)/bigWordNibbles+1)
	end := len(raw)
	for i := range words {
		start := end - bigWordNibbles
		if start < 0 {
			start = 0
		}
		for ri := start; ri < end; ri++ {
			nib := decodeNibble(raw[ri])
			if nib == badNibble {
				return hexutil.ErrSyntax
			}
			words[i] *= 16
			words[i] += big.Word(nib)
		}
		end = start
	}
	var dec big.Int
	dec.SetBits(words)
	*b = (Big)(dec)
	return nil
}

func (b *Big) String() string {
	return EncodeBig(b.ToInt())
}

func (b *Big) ToInt() *big.Int {
	return (*big.Int)(b)
}



type FakeBigInt struct{
	content string
}

func (obj FakeBigInt) MarshalText() ([]byte, error){
	ret, err := hex.DecodeString(obj.content)
	return ret, err
}

func (obj *FakeBigInt) UnmarshalText(input []byte) error{
	obj.content = hex.EncodeToString(input[:])
	log.Printf("-------------- : " + obj.content)
	return nil
}

func (obj *FakeBigInt) String() string{
	return obj.content
}


type BlockHeader struct {
	ParentHash  common.Hash    `json:"parentHash"       gencodec:"required"`
	UncleHash   common.Hash    `json:"sha3Uncles"       gencodec:"required"`
	Coinbase    common.Address `json:"miner"            gencodec:"required"`
	Root        common.Hash    `json:"stateRoot"        gencodec:"required"`
	TxHash      common.Hash    `json:"transactionsRoot" gencodec:"required"`
	ReceiptHash common.Hash    `json:"receiptsRoot"     gencodec:"required"`
	Bloom       BloomType      `json:"logsBloom"        gencodec:"required"`
	Difficulty  hexutil.Uint64 `json:"difficulty"       gencodec:"required"`
	Number      hexutil.Uint64 `json:"number"           gencodec:"required"`
	GasLimit    hexutil.Uint64 `json:"gasLimit"         gencodec:"required"`
	GasUsed     hexutil.Uint64 `json:"gasUsed"          gencodec:"required"`
	Time        hexutil.Uint64 `json:"timestamp"        gencodec:"required"`
	Extra       hexutil.Bytes  `json:"extraData"        gencodec:"required"`
	MixDigest   common.Hash    `json:"mixHash"          gencodec:"required"`
	Nonce       BlockNonce     `json:"nonce"            gencodec:"required"`
}

func (h *BlockHeader) Hash() common.Hash {
	return rlpHash(h)
}

// HashNoNonce returns the hash which is used as input for the proof-of-work search.
func (h *BlockHeader) HashNoNonce() common.Hash {
	return rlpHash([]interface{}{
		h.ParentHash,
		h.UncleHash,
		h.Coinbase,
		h.Root,
		h.TxHash,
		h.ReceiptHash,
		h.Bloom,
		h.Difficulty,
		h.Number,
		h.GasLimit,
		h.GasUsed,
		h.Time,
		h.Extra,
	})
}

func rlpHash(x interface{}) (h common.Hash) {
	hw := sha3.NewKeccak256()
	rlp.Encode(hw, x)
	hw.Sum(h[:0])
	return h
}

type Block struct {
	Header       *BlockHeader
	uncles       []*BlockHeader
}


type GetBlockReplyPart struct {
	Number     string `json:"number"`
	Difficulty string `json:"difficulty"`
}

const receiptStatusSuccessful = "0x1"

type TxReceipt struct {
	TxHash    string `json:"transactionHash"`
	GasUsed   string `json:"gasUsed"`
	BlockHash string `json:"blockHash"`
	Status    string `json:"status"`
}

func (r *TxReceipt) Confirmed() bool {
	return len(r.BlockHash) > 0
}

// Use with previous method
func (r *TxReceipt) Successful() bool {
	if len(r.Status) > 0 {
		return r.Status == receiptStatusSuccessful
	}
	return true
}

type Tx struct {
	Gas      string `json:"gas"`
	GasPrice string `json:"gasPrice"`
	Hash     string `json:"hash"`
}

type JSONRpcResp struct {
	Id     *json.RawMessage       `json:"id"`
	Result *json.RawMessage       `json:"result"`
	Error  map[string]interface{} `json:"error"`
}

func NewRPCClient(name, url, timeout string) *RPCClient {
	rpcClient := &RPCClient{Name: name, Url: url}
	timeoutIntv := util.MustParseDuration(timeout)
	rpcClient.client = &http.Client{
		Timeout: timeoutIntv,
	}
	return rpcClient
}

func (r *RPCClient) GetWork() ([]string, error) {
	rpcResp, err := r.doPost(r.Url, "eth_getWork", []string{})
	if err != nil {
		return nil, err
	}
	var reply []string
	err = json.Unmarshal(*rpcResp.Result, &reply)
	return reply, err
}

func (r *RPCClient) GetPendingBlock() (*GetBlockReplyPart, error) {
	rpcResp, err := r.doPost(r.Url, "eth_getBlockByNumber", []interface{}{"pending", false})
	if err != nil {
		return nil, err
	}
	if rpcResp.Result != nil {
		var reply *GetBlockReplyPart
		err = json.Unmarshal(*rpcResp.Result, &reply)
		return reply, err
	}
	return nil, nil
}

func (r *RPCClient) GetBlockByHeight(height int64) (*GetBlockReply, error) {
	params := []interface{}{fmt.Sprintf("0x%x", height), true}
	return r.getBlockBy("eth_getBlockByNumber", params)
}

func (r *RPCClient) Init() {
	// This is a weird way to compute the number of nibbles required for big.Word.
	// The usual way would be to use constant arithmetic but go vet can't handle that.
	b, _ := new(big.Int).SetString("FFFFFFFFFF", 16)
	switch len(b.Bits()) {
	case 1:
		bigWordNibbles = 16
	case 2:
		bigWordNibbles = 8
	default:
		panic("weird big.Word size")
	}
}
////////////////////////////////////////////////////
////////////////////////////////////////////////////
func (r *RPCClient) GetBlockRLP(height int64) (string){
	params := []interface{}{height}
	method := "debug_getBlockRlp"
	rpcResp, err := r.doPost(r.Url, method, params)
	if err != nil {
		return "!!!!!!!!!!!!!!!! err: " + err.Error()
	}
	
	if rpcResp.Result != nil {
		rlpData, error := json.Marshal(&rpcResp.Result)
		if(error == nil){
			return "!!!!!!!!!!!!!!!! we got something: " + string(rlpData)
		}
		return "!!!!!!!!!!!!!!!! we got something error"
	}
	return "nil"
}

func (r *RPCClient) GetHeaderRLP(height int64){
	r.Init()
	params := []interface{}{fmt.Sprintf("0x%x", height), true}
	method := "eth_getBlockByNumber"
	
	rpcResp, err := r.doPost(r.Url, method, params)
	if err != nil {
		log.Printf("!!!!!!!!!!!!!!!! err: " + err.Error())
		return 
	}
	
	if rpcResp.Result != nil {
		var header *BlockHeader
		err = json.Unmarshal(*rpcResp.Result, &header)
		//cannot unmarshal "0xc24c3" into a *big.Int
		if(err != nil){
			log.Printf("!!!!!!!#######GetHeaderRLP Unmarshal json data error: "+err.Error())
			return
		}
		
		log.Printf("ParentHash: "+header.ParentHash.String())
		log.Printf("UncleHash: "+header.UncleHash.String())
		log.Printf("Coinbase: "+header.Coinbase.String())
		log.Printf("Root: "+header.Root.String())
		log.Printf("TxHash: "+header.TxHash.String())
		log.Printf("ReceiptHash: "+header.ReceiptHash.String())
		log.Printf("Bloom: "+header.Bloom.String())
		log.Printf("Difficulty: "+header.Difficulty.String())
		log.Printf("Number: "+header.Number.String())
		log.Printf("GasLimit: "+header.GasLimit.String())
		log.Printf("GasUsed: "+header.GasUsed.String())
		log.Printf("Time: "+header.Time.String())
		log.Printf("Extra: "+header.Extra.String())
		log.Printf("MixDigest: "+header.MixDigest.String())
		log.Printf("Nonce: "+header.Nonce.String())
		
		headerRlpByte, hErr := rlp.EncodeToBytes(header)
		if(hErr != nil){
			log.Printf("header EncodeToBytes error: ", hErr.Error())
			return
		}
		
		log.Printf("headerRlpByte::::::", hex.EncodeToString(headerRlpByte[:]))
		
		log.Printf("++++++++++++++++++++++++++")
		log.Printf("header hash A: ", header.Hash().String())
		hw := sha3.NewKeccak256()
		hw.Write(headerRlpByte)
		var h common.Hash
		hw.Sum(h[:0])
		log.Printf("header hash B: ", h.String())
	}
}


func (r *RPCClient) GetBlockHeaderRLP(height int64){
	params := []interface{}{height}
	method := "debug_getBlockRlp"
	rpcResp, err := r.doPost(r.Url, method, params)
	if err != nil {
		log.Printf("!!!!!!!!!!!!!!!! err: " + err.Error())
		return 
	}
	
	if rpcResp.Result != nil {
		rlpBytes, _ := json.Marshal(&rpcResp.Result)
		rlpStr 	 := string(rlpBytes)
		log.Printf("rlpStr from RPC result", rlpStr)
		log.Printf("rlpBytes len: ", len(rlpBytes))
		
		rlp.ListSize(15)
		var header *BlockHeader
		rlpErr := rlp.DecodeBytes(rlpBytes, &header)
		if(rlpErr != nil){
			log.Printf("%%%%%%%%%%%%%%% rlpErr : " + rlpErr.Error())
			return
		}
		log.Printf("header ParentHash : "+header.ParentHash.String())
		
		// var block types.Block
		// log.Printf(block.Hash().String())
		// rlpErr := rlp.DecodeBytes(rlpBytes, &block)
		// if rlpErr != nil {
			// log.Printf("!!!!!!!!!!!!!! decode block RLP data error: " + rlpErr.Error())
			// return
		// }
		
		// log.Printf("block hash: ", string(block.Hash().String()))
		// header := block.Header()
		// headerHash := header.Hash()
		
		// log.Printf("header hash: ", string(headerHash.String()))
		
		////headerNoNonceHash := header.HashNoNonce()
		
		// headerRlpByte, hErr := rlp.EncodeToBytes(header)
		// if(hErr != nil){
			// log.Printf("header EncodeToBytes error: ", hErr.Error())
			// return
		// }
		
		// log.Printf("headerRlpByte::::::", string(headerRlpByte))
	}
}

func (r *RPCClient) GetBlockByHash(hash string) (*GetBlockReply, error) {
	params := []interface{}{hash, true}
	return r.getBlockBy("eth_getBlockByHash", params)
}

func (r *RPCClient) GetUncleByBlockNumberAndIndex(height int64, index int) (*GetBlockReply, error) {
	params := []interface{}{fmt.Sprintf("0x%x", height), fmt.Sprintf("0x%x", index)}
	return r.getBlockBy("eth_getUncleByBlockNumberAndIndex", params)
}

func (r *RPCClient) getBlockBy(method string, params []interface{}) (*GetBlockReply, error) {
	rpcResp, err := r.doPost(r.Url, method, params)
	if err != nil {
		return nil, err
	}
	if rpcResp.Result != nil {
		var reply *GetBlockReply
		err = json.Unmarshal(*rpcResp.Result, &reply)
		return reply, err
	}
	return nil, nil
}

// func (r *RPCClient) getBlock(height int64) (*types.Block){
	// params := []interface{}{height}
	// method := "eth_getBlockByNumber"
	// rpcResp, err := r.doPost(r.Url, method, params)
	// if err != nil {
		// return nil
	// }
	
	// var block *types.Block
	// err = json.Unmarshal(*rpcResp.Result, &block)
	// return nil
// }

func (r *RPCClient) GetTxReceipt(hash string) (*TxReceipt, error) {
	rpcResp, err := r.doPost(r.Url, "eth_getTransactionReceipt", []string{hash})
	if err != nil {
		return nil, err
	}
	if rpcResp.Result != nil {
		var reply *TxReceipt
		err = json.Unmarshal(*rpcResp.Result, &reply)
		return reply, err
	}
	return nil, nil
}

func (r *RPCClient) SubmitBlock(params []string) (bool, error) {
	rpcResp, err := r.doPost(r.Url, "eth_submitWork", params)
	if err != nil {
		return false, err
	}
	var reply bool
	err = json.Unmarshal(*rpcResp.Result, &reply)
	return reply, err
}

func (r *RPCClient) GetBalance(address string) (*big.Int, error) {
	rpcResp, err := r.doPost(r.Url, "eth_getBalance", []string{address, "latest"})
	if err != nil {
		return nil, err
	}
	var reply string
	err = json.Unmarshal(*rpcResp.Result, &reply)
	if err != nil {
		return nil, err
	}
	return util.String2Big(reply), err
}

func (r *RPCClient) Sign(from string, s string) (string, error) {
	hash := sha256.Sum256([]byte(s))
	rpcResp, err := r.doPost(r.Url, "eth_sign", []string{from, common.ToHex(hash[:])})
	var reply string
	if err != nil {
		return reply, err
	}
	err = json.Unmarshal(*rpcResp.Result, &reply)
	if err != nil {
		return reply, err
	}
	if util.IsZeroHash(reply) {
		err = errors.New("Can't sign message, perhaps account is locked")
	}
	return reply, err
}

func (r *RPCClient) GetPeerCount() (int64, error) {
	rpcResp, err := r.doPost(r.Url, "net_peerCount", nil)
	if err != nil {
		return 0, err
	}
	var reply string
	err = json.Unmarshal(*rpcResp.Result, &reply)
	if err != nil {
		return 0, err
	}
	return strconv.ParseInt(strings.Replace(reply, "0x", "", -1), 16, 64)
}

func (r *RPCClient) SendTransaction(from, to, gas, gasPrice, value string, autoGas bool) (string, error) {
	params := map[string]string{
		"from":  from,
		"to":    to,
		"value": value,
	}
	if !autoGas {
		params["gas"] = gas
		params["gasPrice"] = gasPrice
	}
	rpcResp, err := r.doPost(r.Url, "eth_sendTransaction", []interface{}{params})
	var reply string
	if err != nil {
		return reply, err
	}
	err = json.Unmarshal(*rpcResp.Result, &reply)
	if err != nil {
		return reply, err
	}
	/* There is an inconsistence in a "standard". Geth returns error if it can't unlock signer account,
	 * but Parity returns zero hash 0x000... if it can't send tx, so we must handle this case.
	 * https://github.com/ethereum/wiki/wiki/JSON-RPC#returns-22
	 */
	if util.IsZeroHash(reply) {
		err = errors.New("transaction is not yet available")
	}
	return reply, err
}

func (r *RPCClient) doPost(url string, method string, params interface{}) (*JSONRpcResp, error) {
	jsonReq := map[string]interface{}{"jsonrpc": "2.0", "method": method, "params": params, "id": 0}
	data, _ := json.Marshal(jsonReq)

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(data))
	req.Header.Set("Content-Length", (string)(len(data)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := r.client.Do(req)
	if err != nil {
		r.markSick()
		return nil, err
	}
	defer resp.Body.Close()

	var rpcResp *JSONRpcResp
	err = json.NewDecoder(resp.Body).Decode(&rpcResp)
	if err != nil {
		r.markSick()
		return nil, err
	}
	if rpcResp.Error != nil {
		r.markSick()
		return nil, errors.New(rpcResp.Error["message"].(string))
	}
	return rpcResp, err
}

func (r *RPCClient) Check() bool {
	_, err := r.GetWork()
	if err != nil {
		return false
	}
	r.markAlive()
	return !r.Sick()
}

func (r *RPCClient) Sick() bool {
	r.RLock()
	defer r.RUnlock()
	return r.sick
}

func (r *RPCClient) markSick() {
	r.Lock()
	r.sickRate++
	r.successRate = 0
	if r.sickRate >= 5 {
		r.sick = true
	}
	r.Unlock()
}

func (r *RPCClient) markAlive() {
	r.Lock()
	r.successRate++
	if r.successRate >= 5 {
		r.sick = false
		r.sickRate = 0
		r.successRate = 0
	}
	r.Unlock()
}
