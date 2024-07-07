from . import db


user_organisation = db.Table(
    'user_organisation',
    db.Column('userId', db.String, db.ForeignKey('user.userId')),
    db.Column('orgId', db.String, db.ForeignKey('organisation.orgId'))
)


class User(db.Model):

    userId = db.Column(db.String(100), primary_key=True)
    firstName = db.Column(db.String(100), nullable=False)
    lastName = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False, unique=True)
    phone = db.Column(db.String(100), nullable=True)
    password = db.Column(db.String(250), nullable=False)
    organisations = db.relationship('Organisation', secondary=user_organisation, backref='users')

    def get_user_details(self):
        return {
            "userid": self.userId,
            "firstName": self.firstName,
            "lastName": self.lastName,
            "email": self.email,
            "phone": self.phone,
        }


    def __repr__(self) -> str:
        return f"<User: {self.userId}>"

class Organisation(db.Model):
    orgId = db.Column(db.String(60), primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(100), nullable=True)

    def __repr__(self) -> str:
        return f"<Organisation: {self.name}>"

