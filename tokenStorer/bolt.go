package tokenStorer

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/err0r500/go-solid-server/uc"

	"github.com/boltdb/bolt"
)

type boltStorage struct {
	tokenMaxAge int64
	db          *bolt.DB
}

func New(path string) uc.TokenStorer {
	db, err := bolt.Open(path, 0644, nil)
	if err != nil {
		log.Fatal("failed to start bolt db")
	}
	return boltStorage{db: db}
}

// NewToken saves an API token to the bolt db. It returns the API token and a possible error
func (s boltStorage) NewPersistedToken(tokenType, host string, values map[string]string) (string, error) {
	var token string
	if len(tokenType) == 0 || len(host) == 0 {
		return token, errors.New("Can't retrieve token from db. Missing values for token or host.")
	}

	// bucket(host) -> bucket(type) -> values
	err := s.db.Update(func(tx *bolt.Tx) error {
		userBucket, err := tx.CreateBucketIfNotExists([]byte(host))
		if err != nil {
			return err
		}
		bucket, err := userBucket.CreateBucketIfNotExists([]byte(tokenType))
		id, _ := bucket.NextSequence()
		values["id"] = fmt.Sprintf("%d", id)
		// set validity if not alreay set
		if len(values["valid"]) == 0 {
			// age times the duration of 6 month
			values["valid"] = fmt.Sprintf("%d", time.Now().Add(time.Duration(s.tokenMaxAge)*time.Hour*5040).Unix())
		}
		// marshal values to JSON
		tokenJson, err := json.Marshal(values)
		if err != nil {
			return err
		}
		token = fmt.Sprintf("%x", sha256.Sum256(tokenJson))
		err = bucket.Put([]byte(token), tokenJson)
		if err != nil {
			return err
		}

		return nil
	})

	return token, err
}

func (s boltStorage) GetPersistedToken(tokenType, host, token string) (map[string]string, error) {
	tokenValues := map[string]string{}
	if len(tokenType) == 0 || len(host) == 0 || len(token) == 0 {
		return tokenValues, errors.New("Can't retrieve token from db. tokenType, host and token value are requrired.")
	}
	err := s.db.View(func(tx *bolt.Tx) error {
		userBucket := tx.Bucket([]byte(host))
		if userBucket == nil {
			return errors.New(host + " bucket not found!")
		}
		bucket := userBucket.Bucket([]byte(tokenType))
		if bucket == nil {
			return errors.New(tokenType + " bucket not found!")
		}

		// unmarshal
		b := bucket.Get([]byte(token))
		err := json.Unmarshal(b, &tokenValues)
		return err
	})
	return tokenValues, err
}

func (s boltStorage) GetTokenByOrigin(tokenType, host, origin string) (string, error) {
	token := ""
	if len(tokenType) == 0 || len(host) == 0 || len(origin) == 0 {
		return token, errors.New("Can't retrieve token from db. tokenType, host and token value are requrired.")
	}

	err := s.db.View(func(tx *bolt.Tx) error {
		userBucket := tx.Bucket([]byte(host))
		if userBucket == nil {
			return errors.New(host + " bucket not found!")
		}
		bucket := userBucket.Bucket([]byte(tokenType))
		if bucket == nil {
			return errors.New(tokenType + " bucket not found!")
		}

		// unmarshal
		c := bucket.Cursor()

		for k, _ := c.First(); k != nil; k, _ = c.Next() {
			key := string(k)
			values, err := s.GetPersistedToken(tokenType, host, key)
			if err == nil && values["origin"] == origin {
				token = key
				break
			}
		}

		return nil
	})

	return token, err
}

func (s boltStorage) GetTokensByType(tokenType, host string) (map[string]map[string]string, error) {
	tokens := make(map[string]map[string]string)
	err := s.db.View(func(tx *bolt.Tx) error {
		// Assume bucket exists and has keys
		b := tx.Bucket([]byte(host))
		if b == nil {
			return errors.New("No bucket for host " + host)
		}
		ba := b.Bucket([]byte(tokenType))
		if ba == nil {
			return errors.New("No bucket for type " + tokenType)
		}

		c := ba.Cursor()

		for k, _ := c.First(); k != nil; k, _ = c.Next() {
			key := string(k)
			token, err := s.GetPersistedToken(tokenType, host, key)
			if err == nil {
				tokens[key] = token
			}
		}
		return nil
	})
	return tokens, err
}

func (s boltStorage) DeletePersistedToken(tokenType, host, token string) error {
	if len(tokenType) == 0 || len(host) == 0 || len(token) == 0 {
		return errors.New("Can't retrieve token from db. tokenType, host and token value are requrired.")
	}
	err := s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(host)).Bucket([]byte(tokenType)).Delete([]byte(token))
	})

	return err
}
