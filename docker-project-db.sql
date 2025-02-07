CREATE USER 'flask_user'@'%' IDENTIFIED BY 'Abhiram@1729';
GRANT ALL PRIVILEGES ON *.* TO 'flask_user'@'%' WITH GRANT OPTION;
FLUSH PRIVILEGES;
CREATE DATABASE docker_management;
USE docker_management;
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL UNIQUE,
    password_hash VARCHAR(200) NOT NULL
);
CREATE TABLE IF NOT EXISTS scan_reports (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    scanner_name VARCHAR(255) NOT NULL,
    file_name VARCHAR(255) NOT NULL,  -- Store the actual file name
    report_text LONGTEXT NOT NULL,    -- Store scan results
    scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

SELECT host, user FROM mysql.user WHERE user='flask_user';
