FROM node:8

#copy files to the /var/www/html directory
COPY . .

# you can either get the data while building an image or perform docker exec
#RUN wget https://raw.githubusercontent.com/mongodb/docs-assets/primer-dataset/primer-dataset.json
RUN npm clean-install

# run node index.js file
CMD ["node", "index.js"]
