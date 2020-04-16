CREATE DATABASE auth;

USE auth;

CREATE TABLE users (
    username VARCHAR(20),
    hashedPassword VARCHAR(60)
);