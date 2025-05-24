from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import uuid

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'

    user_id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    organization_id = db.Column(db.String(36), nullable=False)
    user_username = db.Column(db.String(20), nullable=False, unique=True)
    user_password = db.Column(db.String(100), nullable=False)
    user_salt = db.Column(db.String(100), nullable=False)
    user_name = db.Column(db.String(50), nullable=False)
    user_email = db.Column(db.String(50))
    user_phone = db.Column(db.String(20))
    user_creation_time = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_created_by = db.Column(db.String(50))
    user_is_super_admin = db.Column(db.Boolean, nullable=False, default=False)
    user_is_disabled = db.Column(db.Boolean, nullable=False, default=False)

    def __repr__(self):
        return f'<User {self.user_username}>'

class UserRoleAssociation(db.Model):
    __tablename__ = 'user_role_association'

    user_id = db.Column(db.String(36), db.ForeignKey('users.user_id'), primary_key=True, nullable=False)
    role_id = db.Column(db.String(36), primary_key=True, nullable=False)
    application_id = db.Column(db.String(36), primary_key=True, nullable=False)
    assoc_creation_time = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    assoc_created_by = db.Column(db.String(50))
    assoc_desc = db.Column(db.String(255))
    assoc_expiry_date = db.Column(db.Date)
    assoc_api_token = db.Column(db.Text)  # Assuming citext is similar to Text in SQLAlchemy

    def __repr__(self):
        return f'<UserRoleAssociation {self.user_id}, {self.role_id}, {self.application_id}>'

class SoftwareComponent(db.Model):
    __tablename__ = 'software_component'

    component_id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    component_name = db.Column(db.String(15))
    component_desc = db.Column(db.String(255))
    component_has_api = db.Column(db.Boolean)

    def __repr__(self):
        return f'<SoftwareComponent {self.component_name}>'

class Role(db.Model):
    __tablename__ = 'role'

    role_id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    component_id = db.Column(db.String(36), db.ForeignKey('software_component.component_id'), nullable=False)
    role_name = db.Column(db.String(15))
    role_desc = db.Column(db.String(255))

    def __repr__(self):
        return f'<Role {self.role_name}>'

 