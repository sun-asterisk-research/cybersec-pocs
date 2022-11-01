#!/bin/bash
echo "Creating MySQL user and database"

mysql -u root -p$(echo $MYSQL_ROOT_PASSWORD) <<MYSQL_SCRIPT
CREATE USER '$(cat user)';
GRANT ALL PRIVILEGES ON *.* TO '$(cat user)'@'%';
FLUSH PRIVILEGES;
MYSQL_SCRIPT

echo "MySQL user and database created."
echo "Username:   $(cat user)"