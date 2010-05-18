from google.appengine.ext import db

class UserGroup(db.Model):
    name = db.StringProperty(required=True)

class UserRole(db.Model):
    name = db.StringProperty(required=True)

class BaseUser(db.Model):
    username = db.StringProperty(required=True)
    password = db.StringProperty()
    created = db.DateTimeProperty(auto_now_add=True)
    group = db.ReferenceProperty(UserGroup)
    roles = db.ListProperty(db.Key)

