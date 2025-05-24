from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS

#Here  are creating an instance of the SQLAlchemy class and assigning it to the variable db.
# This instance will be used throughout application to define and manage models and interact with the database.

cors = CORS()
db = SQLAlchemy()


