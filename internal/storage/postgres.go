package storage

import (
	"fmt"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
)

type PostgresStorage struct {
	*sqlx.DB
}

func NewPostgresStorage(host string, port int, user, password, dbname string) (*PostgresStorage, error) {
	psqlInfo := fmt.Sprintf("host=%s port=%d user=%s "+
		"password=%s dbname=%s sslmode=disable",
		host, port, user, password, dbname)
	db, err := sqlx.Connect("postgres", psqlInfo)
	if err != nil {
		return nil, err
	}
	return &PostgresStorage{db}, nil
}

func (storage *PostgresStorage) PutEntry(srctxn string, pubkey, z, r, s []byte) error {
	_, err := storage.Exec("INSERT into sighash(srctxn, pubkey, z, r, s) VALUES($1, $2, $3, $4, $5)",
		srctxn, pubkey, z, r, s)
	if err != nil {
		return err
	}
	return nil
}
