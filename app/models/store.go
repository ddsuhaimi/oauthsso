package models

import (
	"errors"
	"sync"
	"time"
)

var (
	ErrNotFound      = errors.New("record not found")
	ErrAlreadyExists = errors.New("record already exists")
	ErrInvalidToken  = errors.New("invalid token")
	ErrExpiredToken  = errors.New("token has expired")
)

// Store defines the interface for data persistence
type Store interface {
	// User operations
	CreateUser(user *User) error
	GetUserByID(id string) (*User, error)
	GetUserByEmail(email string) (*User, error)
	UpdateUser(user *User) error
	ListUsers() ([]*User, error)

	// Client operations
	CreateClient(client *Client) error
	GetClientByID(id string) (*Client, error)
	ListClients() ([]*Client, error)

	// Auth code operations
	SaveAuthCode(code *AuthCode) error
	GetAuthCode(code string) (*AuthCode, error)
	DeleteAuthCode(code string) error

	// Token operations
	SaveToken(token *Token) error
	GetTokenByAccessJTI(jti string) (*Token, error)
	GetTokenByRefreshJTI(jti string) (*Token, error)
	DeleteToken(accessJTI string) error
	RevokeAllUserTokens(userID string) error
}

// InMemoryStore implements Store with in-memory maps
type InMemoryStore struct {
	users     map[string]*User            // Indexed by ID
	usersByEmail map[string]*User         // Indexed by email
	clients   map[string]*Client          // Indexed by ID
	authCodes map[string]*AuthCode        // Indexed by code
	tokens    map[string]*Token           // Indexed by access JTI
	tokensByRefresh map[string]*Token     // Indexed by refresh JTI
	mu        sync.RWMutex
}

// NewInMemoryStore creates a new in-memory store
func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{
		users:     make(map[string]*User),
		usersByEmail: make(map[string]*User),
		clients:   make(map[string]*Client),
		authCodes: make(map[string]*AuthCode),
		tokens:    make(map[string]*Token),
		tokensByRefresh: make(map[string]*Token),
	}
}

// User operations

func (s *InMemoryStore) CreateUser(user *User) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.usersByEmail[user.Email]; exists {
		return ErrAlreadyExists
	}

	s.users[user.ID] = user
	s.usersByEmail[user.Email] = user
	return nil
}

func (s *InMemoryStore) GetUserByID(id string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	user, exists := s.users[id]
	if !exists {
		return nil, ErrNotFound
	}
	return user, nil
}

func (s *InMemoryStore) GetUserByEmail(email string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	user, exists := s.usersByEmail[email]
	if !exists {
		return nil, ErrNotFound
	}
	return user, nil
}

func (s *InMemoryStore) UpdateUser(user *User) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.users[user.ID]; !exists {
		return ErrNotFound
	}

	// Update both indexes
	s.users[user.ID] = user
	s.usersByEmail[user.Email] = user
	return nil
}

func (s *InMemoryStore) ListUsers() ([]*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	users := make([]*User, 0, len(s.users))
	for _, user := range s.users {
		users = append(users, user)
	}
	return users, nil
}

// Client operations

func (s *InMemoryStore) CreateClient(client *Client) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.clients[client.ID]; exists {
		return ErrAlreadyExists
	}

	s.clients[client.ID] = client
	return nil
}

func (s *InMemoryStore) GetClientByID(id string) (*Client, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	client, exists := s.clients[id]
	if !exists {
		return nil, ErrNotFound
	}
	return client, nil
}

func (s *InMemoryStore) ListClients() ([]*Client, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	clients := make([]*Client, 0, len(s.clients))
	for _, client := range s.clients {
		clients = append(clients, client)
	}
	return clients, nil
}

// Auth code operations

func (s *InMemoryStore) SaveAuthCode(code *AuthCode) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.authCodes[code.Code] = code
	return nil
}

func (s *InMemoryStore) GetAuthCode(code string) (*AuthCode, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	authCode, exists := s.authCodes[code]
	if !exists {
		return nil, ErrNotFound
	}

	// Check if the code has expired
	if time.Now().After(authCode.ExpiresAt) {
		return nil, ErrExpiredToken
	}

	return authCode, nil
}

func (s *InMemoryStore) DeleteAuthCode(code string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.authCodes[code]; !exists {
		return ErrNotFound
	}

	delete(s.authCodes, code)
	return nil
}

// Token operations

func (s *InMemoryStore) SaveToken(token *Token) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.tokens[token.AccessJTI] = token
	if token.RefreshJTI != "" {
		s.tokensByRefresh[token.RefreshJTI] = token
	}
	return nil
}

func (s *InMemoryStore) GetTokenByAccessJTI(jti string) (*Token, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	token, exists := s.tokens[jti]
	if !exists {
		return nil, ErrNotFound
	}

	// Check if the token has expired
	if time.Now().After(token.ExpiresAt) {
		return nil, ErrExpiredToken
	}

	return token, nil
}

func (s *InMemoryStore) GetTokenByRefreshJTI(jti string) (*Token, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	token, exists := s.tokensByRefresh[jti]
	if !exists {
		return nil, ErrNotFound
	}

	// Check if the token has expired
	if time.Now().After(token.ExpiresAt) {
		return nil, ErrExpiredToken
	}

	return token, nil
}

func (s *InMemoryStore) DeleteToken(accessJTI string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	token, exists := s.tokens[accessJTI]
	if !exists {
		return ErrNotFound
	}

	delete(s.tokens, accessJTI)
	if token.RefreshJTI != "" {
		delete(s.tokensByRefresh, token.RefreshJTI)
	}
	return nil
}

func (s *InMemoryStore) RevokeAllUserTokens(userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Collect tokens to delete
	var tokensToDelete []string
	for jti, token := range s.tokens {
		if token.UserID == userID {
			tokensToDelete = append(tokensToDelete, jti)
		}
	}

	// Delete collected tokens
	for _, jti := range tokensToDelete {
		token := s.tokens[jti]
		delete(s.tokens, jti)
		if token.RefreshJTI != "" {
			delete(s.tokensByRefresh, token.RefreshJTI)
		}
	}

	return nil
} 