# Use the official Nginx image as the base
FROM nginx:latest

# Remove the default Nginx configuration file
RUN rm /etc/nginx/nginx.conf

# Copy your custom configuration file from the build context
# to the location where Nginx expects it
COPY nginx.conf /etc/nginx/nginx.conf