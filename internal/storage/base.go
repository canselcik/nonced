package storage

type Storage interface {
	PutEntry(srctxn string, pubkey, z, r, s []byte) error
}

type NullStorage struct {}

func NewNullStorage() Storage {
	return &NullStorage{}
}

func (storage *NullStorage) PutEntry(srctxn string, pubkey, z, r, s []byte) error {
	return nil
}
