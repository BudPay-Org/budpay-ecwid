# Use the official PHP‑Apache image with PHP 8.1
FROM php:8.1-apache

# Set working directory
WORKDIR /var/www/html

# Install any PHP extensions you need (uncomment examples or add your own)
# RUN docker-php-ext-install pdo_mysql mbstring

# Enable Apache mod_rewrite (optional, but useful for "pretty" URLs)
RUN a2enmod rewrite

# Copy your application code into the container
# Assumes your PHP files and static assets live alongside this Dockerfile
COPY . /var/www/html/

# Ensure permissions (optional; adjust user/group as needed)
RUN chown -R www-data:www-data /var/www/html \
    && find /var/www/html -type d -exec chmod 755 {} \; \
    && find /var/www/html -type f -exec chmod 644 {} \;

# Expose port 80
EXPOSE 80

# Apache runs in the foreground by default in this image, so no CMD needed