CREATE DATABASE auth;

USE auth;

CREATE TABLE Users (
    username text primary key,
    hashedPassword text
);