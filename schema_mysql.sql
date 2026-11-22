-- Auto-generated from SQLAlchemy models.
-- First run create_database.sql to create phone_book_db.
USE phone_book_db;


CREATE TABLE IF NOT EXISTS users (
	id INTEGER NOT NULL AUTO_INCREMENT, 
	username VARCHAR(254),
	full_name VARCHAR(180) NOT NULL, 
	email VARCHAR(254) NOT NULL, 
	phone_number VARCHAR(40) NOT NULL, 
	password_hash VARCHAR(250) NOT NULL, 
	created_at DATETIME NOT NULL, 
	failed_logins INTEGER NOT NULL, 
	locked_until DATETIME, 
	PRIMARY KEY (id)
)

;

CREATE TABLE IF NOT EXISTS contacts (
	id INTEGER NOT NULL AUTO_INCREMENT, 
	user_id INTEGER NOT NULL, 
	name VARCHAR(180) NOT NULL, 
	phone VARCHAR(300) NOT NULL, 
	email VARCHAR(600) NOT NULL, 
	address TEXT NOT NULL, 
	avatar VARCHAR(400) NOT NULL, 
	notes TEXT NOT NULL, 
	is_favorite BOOL NOT NULL, 
	is_deleted BOOL NOT NULL, 
	deleted_at DATETIME, 
	created_at DATETIME NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(user_id) REFERENCES users (id)
)

;

CREATE TABLE IF NOT EXISTS `groups` (
	id INTEGER NOT NULL AUTO_INCREMENT, 
	user_id INTEGER NOT NULL, 
	name VARCHAR(100) NOT NULL, 
	PRIMARY KEY (id), 
	CONSTRAINT uq_user_group_name UNIQUE (user_id, name), 
	FOREIGN KEY(user_id) REFERENCES users (id)
)

;

CREATE TABLE IF NOT EXISTS password_resets (
	id INTEGER NOT NULL AUTO_INCREMENT, 
	user_id INTEGER NOT NULL, 
	code_hash VARCHAR(64) NOT NULL, 
	salt VARCHAR(32) NOT NULL, 
	attempts INTEGER NOT NULL, 
	expires_at DATETIME NOT NULL, 
	used_at DATETIME, 
	PRIMARY KEY (id), 
	FOREIGN KEY(user_id) REFERENCES users (id)
)

;

CREATE TABLE IF NOT EXISTS sessions (
	id INTEGER NOT NULL AUTO_INCREMENT, 
	user_id INTEGER NOT NULL, 
	token_hash VARCHAR(64) NOT NULL, 
	expires_at DATETIME NOT NULL, 
	created_at DATETIME NOT NULL, 
	revoked_at DATETIME, 
	PRIMARY KEY (id), 
	FOREIGN KEY(user_id) REFERENCES users (id)
)

;


CREATE TABLE IF NOT EXISTS contact_groups (
	contact_id INTEGER NOT NULL, 
	group_id INTEGER NOT NULL, 
	PRIMARY KEY (contact_id, group_id), 
	FOREIGN KEY(contact_id) REFERENCES contacts (id) ON DELETE CASCADE, 
	FOREIGN KEY(group_id) REFERENCES `groups` (id) ON DELETE CASCADE
)

;
