CREATE DATABASE auth;
\connect auth 
CREATE TABLE users (
  email VARCHAR(320),
  hashedPassword TEXT,
  verified boolean,
  resetToken bytea,
  verifiedToken TEXT,
  userId uuid
)