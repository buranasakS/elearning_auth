-- name: CreateUser :one
INSERT INTO users (fullname, email, password, role)
VALUES ($1, $2, $3, $4)
RETURNING *;

-- name: CheckEmailExists :one
SELECT id, email, fullname FROM users WHERE email = $1;

-- name: GetUserDetail :one
SELECT id, email, fullname, role FROM users WHERE id = $1;

-- name: GetUserForLogin :one
SELECT id, email, fullname, password, role FROM users WHERE email = $1 LIMIT 1;

-- name: ResetPassword :exec
UPDATE users SET password = $2 WHERE id = $1;

-- name: UpdatePassword :exec
UPDATE users 
SET password = $2, updated_at = NOW()
WHERE id = $1; 