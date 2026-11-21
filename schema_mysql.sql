-- Auto-generated from SQLAlchemy models.
-- First run create_database.sql to create phone_book_db.
USE phone_book_db;


CREATE TABLE IF NOT EXISTS users (
	id INTEGER NOT NULL AUTO_INCREMENT, 
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
