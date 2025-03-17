package utils

import "github.com/jackc/pgx/v5/pgtype"

func ParseUUID(id string) (pgtype.UUID, error) {
	var uuid pgtype.UUID
	err := uuid.Scan(id)
	return uuid, err
}
