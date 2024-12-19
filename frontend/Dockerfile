# Dockerfile for the React frontend
FROM node:16

WORKDIR /app

# Install dependencies
COPY package.json package-lock.json /app/
RUN npm install

# Copy the app code
COPY . /app/

EXPOSE 3000

CMD ["npm", "start"]
