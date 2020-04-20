CREATE DATABASE auth;

USE auth;

CREATE TABLE users (
    email VARCHAR(320),
    hashedPassword VARCHAR(60)
);