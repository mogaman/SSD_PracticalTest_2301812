# Use the official Node.js runtime as the base image
FROM node:18-alpine

# Set the working directory inside the container
WORKDIR /usr/src/app

# Copy package.json and package-lock.json (if available)
COPY package*.json ./
RUN npm install --ignore-scripts

# Copy the rest of the application files
COPY ./src/server.js ./
# MUST COPY ALL FILES INTO WEBSERVER CONTAINER

# Create a non-root user for security
RUN addgroup -g 1001 -S nodejs && \
    adduser -S webserver -u 1001

# Change ownership of the app directory to the nodejs user
RUN chown -R webserver:nodejs /usr/src/app

# Switch to the non-root user
USER webserver

# Expose the port the app runs on
EXPOSE 80

# Start the application
CMD ["npm", "start"]