FROM mariadb:10.1

COPY create_db.sql /
COPY user /user
RUN chmod +x /create_db.bash
RUN /create_db.bash