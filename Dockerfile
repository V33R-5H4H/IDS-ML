# Use the official lightweight Nginx image
FROM nginx:alpine

# Copy all the static HTML/CSS/JS files from the frontend folder
# into Nginx's default serving directory
COPY . /usr/share/nginx/html

# Expose port 80 inside the container
EXPOSE 80

# Start Nginx continuously
CMD ["nginx", "-g", "daemon off;"]
