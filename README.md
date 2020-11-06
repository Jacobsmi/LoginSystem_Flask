# Login System API

- A Flask system that allows for user authorization using JSON Web Tokens and retrieval of information after auth

## To Run

- Clone the repo 
- Create a virtualenv within the repo folder and run the command `pip3 install -r requirements.txt`
- Create an instance of the database of your choice
- Create a .env file and create a variable called DB_URL that is a connection string to the database you have just created
- Also in the .env create a varaible called JWT_SECRET that contains a secret
- After that you can run the command `py app.py m` which will migrate the Model classes to the database
- Then, you can run `py app.py` which will create a local development server with the API running
