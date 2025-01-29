-- DROP USER IF EXISTS 'flask_user'@'localhost';
CREATE USER 'flask_user'@'localhost' IDENTIFIED BY 'Abhiram@1729';
GRANT ALL PRIVILEGES ON docker_management.* TO 'flask_user'@'localhost';
FLUSH PRIVILEGES;
CREATE DATABASE docker_management;
USE docker_management;
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL UNIQUE,
    password_hash VARCHAR(200) NOT NULL
);
select * from users;
SELECT user, host FROM mysql.user WHERE user = 'flask_user';
SHOW GRANTS FOR 'flask_user'@'localhost';
ALTER TABLE users ADD COLUMN is_admin BOOLEAN DEFAULT FALSE;

