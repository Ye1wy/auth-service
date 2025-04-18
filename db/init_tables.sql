CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS users {
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username TEXT NOT NULL,
    password VARCHAR NOT NULL,
    email TEXT NOT NULL
};

CREATE TABLE IF NOT EXISTS token_ban {
    refresh_token TEXT NOT NULL
};