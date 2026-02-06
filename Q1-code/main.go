// Package main implements a simple blockchain with Proof of Work consensus
// and a REST API for interacting with the blockchain
package main

import (
	"crypto/sha256"    // For SHA-256 hashing algorithm
	"encoding/hex"     // For converting bytes to hexadecimal strings
	"encoding/json"    // For JSON encoding/decoding
	"fmt"             // For formatted I/O operations
	"log"             // For logging
	"net/http"        // For HTTP server functionality
	"strconv"         // For string conversions
	"strings"         // For string manipulation
	"time"            // For timestamp operations

	"github.com/gorilla/mux"     // HTTP router and URL matcher
	"github.com/gorilla/handlers" // HTTP handlers for CORS and logging
)

// Transaction represents a transaction in the blockchain
// Contains the transaction data that will be stored in blocks
type Transaction struct {
	Data string `json:"data"` // The actual transaction data/content
}

// Block represents a block in the blockchain
// Each block contains transactions and links to the previous block
type Block struct {
	Index      int           `json:"index"`      // Sequential block number (0, 1, 2, ...)
	Timestamp  string        `json:"timestamp"`  // When the block was created (RFC3339 format)
	Data       []Transaction `json:"data"`       // List of transactions in this block
	PrevHash   string        `json:"prevHash"`   // Hash of the previous block (creates the chain)
	Hash       string        `json:"hash"`       // Current block's hash (calculated from all fields)
	Nonce      int           `json:"nonce"`      // Proof of Work nonce (number used for mining)
	MerkleRoot string        `json:"merkleRoot"` // Merkle tree root hash of all transactions
}

// Blockchain represents the entire blockchain
// Contains a slice of blocks that form the complete chain
type Blockchain struct {
	Chain []Block `json:"chain"` // Array of blocks in chronological order
}

// MerkleNode represents a node in the Merkle tree
// Merkle trees provide efficient verification of transaction integrity
type MerkleNode struct {
	Left  *MerkleNode // Left child node (nil for leaf nodes)
	Right *MerkleNode // Right child node (nil for leaf nodes)
	Data  string      // Hash value stored in this node
}

// Global blockchain instance - stores the main blockchain
// This is shared across all HTTP handlers
var blockchain *Blockchain

// Transaction mempool to store pending transactions
// Transactions wait here until they are included in a mined block
var mempool []Transaction

// CalculateHash calculates the SHA-256 hash of a block
// Combines all block data into a single string and hashes it
func (b *Block) CalculateHash() string {
	// Concatenate all block fields into a single string
	// This ensures any change in block data will result in a different hash
	record := strconv.Itoa(b.Index) + b.Timestamp + b.MerkleRoot + b.PrevHash + strconv.Itoa(b.Nonce)
	
	// Create a new SHA-256 hasher
	h := sha256.New()
	
	// Write the concatenated string to the hasher
	h.Write([]byte(record))
	
	// Get the final hash as a byte slice
	hashed := h.Sum(nil)
	
	// Convert the byte slice to a hexadecimal string
	return hex.EncodeToString(hashed)
}

// CreateMerkleTree creates a Merkle tree from a list of transactions
// Merkle trees allow efficient verification of transaction integrity
func CreateMerkleTree(transactions []Transaction) *MerkleNode {
	// Return nil if no transactions (empty tree)
	if len(transactions) == 0 {
		return nil
	}

	// Slice to store nodes at each level of the tree
	var nodes []*MerkleNode

	// Create leaf nodes - each transaction becomes a leaf
	for _, tx := range transactions {
		// Hash the transaction data to create leaf node
		hash := sha256.Sum256([]byte(tx.Data))
		nodes = append(nodes, &MerkleNode{
			Data: hex.EncodeToString(hash[:]), // Convert hash to hex string
		})
	}

	// If odd number of nodes, duplicate the last one
	// Merkle trees require even number of nodes at each level
	if len(nodes)%2 == 1 {
		nodes = append(nodes, nodes[len(nodes)-1])
	}

	// Build tree bottom-up by combining pairs of nodes
	for len(nodes) > 1 {
		var nextLevel []*MerkleNode
		
		// Process nodes in pairs
		for i := 0; i < len(nodes); i += 2 {
			left := nodes[i]   // Left child
			right := nodes[i+1] // Right child
			
			// Combine left and right node data
			combined := left.Data + right.Data
			
			// Hash the combined data
			hash := sha256.Sum256([]byte(combined))
			
			// Create parent node with combined hash
			nextLevel = append(nextLevel, &MerkleNode{
				Left:  left,  // Link to left child
				Right: right, // Link to right child
				Data:  hex.EncodeToString(hash[:]), // Parent hash
			})
		}
		
		// Move to next level up
		nodes = nextLevel
	}

	// Return the root node (top of the tree)
	return nodes[0]
}

// GetMerkleRoot returns the Merkle root hash from a list of transactions
// The Merkle root is a single hash that represents all transactions in the block
func GetMerkleRoot(transactions []Transaction) string {
	// Return empty string if no transactions
	if len(transactions) == 0 {
		return ""
	}
	
	// Create the Merkle tree from transactions
	tree := CreateMerkleTree(transactions)
	
	// Return empty string if tree creation failed
	if tree == nil {
		return ""
	}
	
	// Return the root node's data (the Merkle root hash)
	return tree.Data
}

// MineBlock mines a new block using Proof of Work consensus algorithm
// Difficulty determines how many leading zeros the hash must have
func (b *Block) MineBlock(difficulty int) {
	// Create target string with required number of leading zeros
	// e.g., difficulty 4 means hash must start with "0000"
	target := strings.Repeat("0", difficulty)
	
	// Keep trying different nonce values until we find a valid hash
	for {
		// Calculate hash with current nonce value
		hash := b.CalculateHash()
		
		// Check if hash meets the difficulty requirement
		if hash[:difficulty] == target {
			// Found valid hash! Set it and exit
			b.Hash = hash
			break
		}
		
		// Increment nonce and try again
		// This changes the hash, allowing us to find a valid one
		b.Nonce++
	}
}

// NewBlock creates a new block with the given parameters
// This function handles block creation and mining
func NewBlock(index int, data []Transaction, prevHash string) *Block {
	// Calculate Merkle root from transaction data
	merkleRoot := GetMerkleRoot(data)
	
	// Create new block with initial values
	block := &Block{
		Index:      index,                           // Block number in sequence
		Timestamp:  time.Now().Format(time.RFC3339), // Current timestamp in ISO format
		Data:       data,                            // List of transactions
		PrevHash:   prevHash,                        // Hash of previous block
		Nonce:      0,                               // Start nonce at 0
		MerkleRoot: merkleRoot,                      // Merkle root of transactions
	}
	
	// Mine the block with difficulty 4 (hash must start with "0000")
	// This is the computationally expensive Proof of Work step
	block.MineBlock(4)
	
	// Return the fully mined block
	return block
}

// NewGenesisBlock creates the genesis block (first block in the blockchain)
// The genesis block has no previous block, so it uses "0" as prevHash
func NewGenesisBlock() *Block {
	// Create a special transaction for the genesis block
	genesisData := []Transaction{{Data: "Genesis Block"}}
	
	// Create block with index 0 and "0" as previous hash
	// This establishes the beginning of the blockchain
	return NewBlock(0, genesisData, "0")
}

// NewBlockchain creates a new blockchain with a genesis block
// Every blockchain must start with a genesis block
func NewBlockchain() *Blockchain {
	// Create blockchain with only the genesis block
	return &Blockchain{
		Chain: []Block{*NewGenesisBlock()}, // Initialize with genesis block
	}
}

// AddBlock adds a new block to the blockchain
// This function handles the process of adding a new block to the chain
func (bc *Blockchain) AddBlock(data []Transaction) {
	// Get the last block in the chain (most recent block)
	prevBlock := bc.Chain[len(bc.Chain)-1]
	
	// Create new block with incremented index and previous block's hash
	newBlock := NewBlock(prevBlock.Index+1, data, prevBlock.Hash)
	
	// Append the new block to the chain
	bc.Chain = append(bc.Chain, *newBlock)
}

// IsValid checks if the blockchain is valid by verifying chain integrity
// This function ensures the blockchain hasn't been tampered with
func (bc *Blockchain) IsValid() bool {
	// Check each block starting from the second block (skip genesis)
	for i := 1; i < len(bc.Chain); i++ {
		currentBlock := bc.Chain[i]  // Current block being validated
		prevBlock := bc.Chain[i-1]   // Previous block in the chain

		// Check if current block's hash is correctly calculated
		// If someone tampered with block data, the hash won't match
		if currentBlock.Hash != currentBlock.CalculateHash() {
			return false // Block data has been modified
		}

		// Check if current block correctly points to previous block
		// This ensures the chain is properly linked
		if currentBlock.PrevHash != prevBlock.Hash {
			return false // Chain link is broken
		}
	}
	
	// If all checks pass, blockchain is valid
	return true
}

// SearchBlockchain searches for data in the blockchain
// Returns all blocks that contain the search query
func (bc *Blockchain) SearchBlockchain(query string) []Block {
	var results []Block // Slice to store matching blocks
	query = strings.ToLower(query) // Convert query to lowercase for case-insensitive search
	
	// Iterate through all blocks in the chain
	for _, block := range bc.Chain {
		// Search in transaction data within each block
		for _, tx := range block.Data {
			// Check if transaction data contains the search query
			if strings.Contains(strings.ToLower(tx.Data), query) {
				results = append(results, block) // Add block to results
				break // Exit inner loop, block already added
			}
		}
		
		// Search in block hash (in case user is looking for specific hash)
		if strings.Contains(strings.ToLower(block.Hash), query) {
			results = append(results, block) // Add block to results
		}
	}
	
	// Return all blocks that matched the search criteria
	return results
}

// ==================== API HANDLERS ====================
// These functions handle HTTP requests and provide REST API endpoints

// GetBlockchain returns the entire blockchain as JSON
// HTTP Method: GET
// Endpoint: /api/blockchain
func GetBlockchain(w http.ResponseWriter, r *http.Request) {
	// Set response header to indicate JSON content
	w.Header().Set("Content-Type", "application/json")
	
	// Encode the blockchain to JSON and send as response
	json.NewEncoder(w).Encode(blockchain)
}

// AddTransaction adds a new transaction to the mempool
// HTTP Method: POST
// Endpoint: /api/transaction
// Body: {"data": "transaction content"}
func AddTransaction(w http.ResponseWriter, r *http.Request) {
	// Define structure to parse incoming JSON request
	var req struct {
		Data string `json:"data"` // Transaction data from request body
	}
	
	// Decode JSON request body into req struct
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// Return error if JSON parsing fails
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	
	// Validate that transaction data is not empty
	if req.Data == "" {
		// Return error if no transaction data provided
		http.Error(w, "Transaction data cannot be empty", http.StatusBadRequest)
		return
	}
	
	// Create new transaction from request data
	transaction := Transaction{Data: req.Data}
	
	// Add transaction to the mempool (pending transactions)
	mempool = append(mempool, transaction)
	
	// Set response header for JSON content
	w.Header().Set("Content-Type", "application/json")
	
	// Send success response with mempool size
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "Transaction added to mempool successfully",
		"mempoolSize": len(mempool), // Current number of pending transactions
	})
}

// MineBlock mines a new block with pending transactions from mempool
// HTTP Method: POST
// Endpoint: /api/mine
// This is where Proof of Work mining happens
func MineBlock(w http.ResponseWriter, r *http.Request) {
	// Check if there are any pending transactions in mempool
	if len(mempool) == 0 {
		// If no transactions, create a block with a default "empty" transaction
		transaction := Transaction{Data: fmt.Sprintf("Empty block mined at %s", time.Now().Format(time.RFC3339))}
		
		// Add the empty block to blockchain
		blockchain.AddBlock([]Transaction{transaction})
		
		// Set response header for JSON content
		w.Header().Set("Content-Type", "application/json")
		
		// Send response indicating empty block was mined
		json.NewEncoder(w).Encode(map[string]interface{}{
			"message": "Empty block mined successfully (no pending transactions)",
			"transactionsInBlock": 1, // Only the default empty transaction
		})
		return
	}
	
	// Create a copy of all pending transactions to mine
	// We copy to avoid modifying the original mempool during mining
	transactionsToMine := make([]Transaction, len(mempool))
	copy(transactionsToMine, mempool)
	
	// Add new block to blockchain with all pending transactions
	// This triggers the mining process (Proof of Work)
	blockchain.AddBlock(transactionsToMine)
	
	// Clear the mempool after successful mining
	// All transactions are now included in the new block
	mempool = []Transaction{}
	
	// Set response header for JSON content
	w.Header().Set("Content-Type", "application/json")
	
	// Send success response with transaction count
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "Block mined successfully with pending transactions",
		"transactionsInBlock": len(transactionsToMine), // Number of transactions included
	})
}

// SearchBlockchain searches for data in the blockchain
// HTTP Method: GET
// Endpoint: /api/search?q=search_term
// Searches through all transactions and block hashes
func SearchBlockchain(w http.ResponseWriter, r *http.Request) {
	// Get search query from URL parameter 'q'
	query := r.URL.Query().Get("q")
	
	// Validate that query parameter is provided
	if query == "" {
		// Return error if no search query provided
		http.Error(w, "Query parameter 'q' is required", http.StatusBadRequest)
		return
	}
	
	// Perform search using blockchain's search method
	results := blockchain.SearchBlockchain(query)
	
	// Set response header for JSON content
	w.Header().Set("Content-Type", "application/json")
	
	// Send search results as JSON response
	json.NewEncoder(w).Encode(map[string]interface{}{
		"query":   query,        // Original search query
		"results": results,      // Array of matching blocks
		"count":   len(results), // Number of blocks found
	})
}

// GetBlockchainInfo returns basic blockchain information and statistics
// HTTP Method: GET
// Endpoint: /api/blockchain/info
// Provides overview of blockchain state
func GetBlockchainInfo(w http.ResponseWriter, r *http.Request) {
	// Create info map with blockchain statistics
	info := map[string]interface{}{
		"length":    len(blockchain.Chain),                    // Total number of blocks
		"isValid":   blockchain.IsValid(),                     // Whether blockchain is valid
		"lastBlock": blockchain.Chain[len(blockchain.Chain)-1], // Most recent block
		"mempoolSize": len(mempool),                           // Number of pending transactions
		"pendingTransactions": mempool,                        // List of pending transactions
	}
	
	// Set response header for JSON content
	w.Header().Set("Content-Type", "application/json")
	
	// Send blockchain info as JSON response
	json.NewEncoder(w).Encode(info)
}

// main function - entry point of the blockchain application
// Sets up the HTTP server, routes, and starts the blockchain
func main() {
	// Initialize the global blockchain with a genesis block
	blockchain = NewBlockchain()
	
	// Create a new HTTP router using Gorilla Mux
	// Mux provides advanced routing capabilities
	r := mux.NewRouter()
	
	// ==================== API ROUTES ====================
	// Define all REST API endpoints and their handlers
	
	r.HandleFunc("/api/blockchain", GetBlockchain).Methods("GET")         // Get entire blockchain
	r.HandleFunc("/api/blockchain/info", GetBlockchainInfo).Methods("GET") // Get blockchain info
	r.HandleFunc("/api/transaction", AddTransaction).Methods("POST")       // Add new transaction
	r.HandleFunc("/api/mine", MineBlock).Methods("POST")                   // Mine new block
	r.HandleFunc("/api/search", SearchBlockchain).Methods("GET")           // Search blockchain
	
	// Serve static files (React frontend application)
	// This serves the built React app from the frontend/build directory
	r.PathPrefix("/").Handler(http.FileServer(http.Dir("./frontend/build/")))
	
	// ==================== CORS CONFIGURATION ====================
	// Enable Cross-Origin Resource Sharing for frontend-backend communication
	corsHandler := handlers.CORS(
		handlers.AllowedOrigins([]string{"*"}),                    // Allow all origins
		handlers.AllowedMethods([]string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}), // Allowed HTTP methods
		handlers.AllowedHeaders([]string{"Content-Type", "Authorization"}), // Allowed headers
	)(r)
	
	// ==================== SERVER STARTUP ====================
	// Print startup information
	fmt.Println("Blockchain server starting on port 8080...")
	fmt.Println("API Endpoints:")
	fmt.Println("  GET  /api/blockchain - View complete blockchain")
	fmt.Println("  GET  /api/blockchain/info - Get blockchain info")
	fmt.Println("  POST /api/transaction - Add transaction")
	fmt.Println("  POST /api/mine - Mine a new block")
	fmt.Println("  GET  /api/search?q=query - Search blockchain")
	
	// Start HTTP server on port 8080
	// log.Fatal will exit the program if server fails to start
	log.Fatal(http.ListenAndServe(":8080", corsHandler))
}
