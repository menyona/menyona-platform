ARG WORDPRESS_IMAGE
FROM ${WORDPRESS_IMAGE}
COPY --chown=www-data:www-data wordpress/ /var/www/html/
COPY --chown=www-data:www-data helpers/ /opt/menyona-lab/
COPY apache-lab.conf /etc/apache2/conf-enabled/menyona-lab.conf
RUN cp -an /usr/src/wordpress/. /var/www/html/ \
    && mkdir -p /var/www/html/wp-content/uploads \
    && chown -R www-data:www-data /var/www/html \
    && sed -i 's/Listen 80/Listen 8080/' /etc/apache2/ports.conf \
    && sed -i 's/:80>/:8080>/' /etc/apache2/sites-available/000-default.conf
ENV APACHE_RUN_DIR=/tmp/apache2 APACHE_PID_FILE=/tmp/apache2/apache2.pid APACHE_LOCK_DIR=/tmp/apache2
USER www-data
