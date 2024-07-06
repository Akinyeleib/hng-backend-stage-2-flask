from . import db

class User(db.Model):
    userId = db.Column(db.String(100), primary_key=True)
    firstName = db.Column(db.String(100), nullable=False)
    lastName = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False, unique=True)
    phone = db.Column(db.String(100), nullable=True)
    password = db.Column(db.String(250), nullable=False)

    def get_user(self):
        return {
            "userid": self.userId,
            "firstName": self.firstName,
            "lastName": self.lastName,
            "email": self.email,
            "phone": self.phone,
        }


class Organisation(db.Model):
    orgId = db.Column(db.String(60), primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(100), nullable=True)

    

