# flask-postgres-if
application that implements an interface between a flask-sqlalchemy application and a postgres sql.

The application container is built using the Dockerfile (right now works with tag py-postgres-if:7 as stated in the docker-compose)
From the application folder, you then run 

$ docker-compose up

this command runs the container for the application and for postgres.

You can use the Postman Collection to run API calls against the REST application.

