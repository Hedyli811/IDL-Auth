from flask import Flask, request, jsonify
from datetime import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
from dotenv import load_dotenv
from cryptography.hazmat.primitives import padding
import base64
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity

from extension import cors
from models import User, db, UserRoleAssociation, Role, SoftwareComponent, Application, UserKey

load_dotenv()

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config['SQLALCHEMY_BINDS'] = {
    'user': os.getenv('USER_DATABASE_URL')
}

app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')  
jwt = JWTManager(app)
db.init_app(app)
cors.init_app(app)

def decrypt_password(encrypted_password, key, iv):
    try:
        # 解码base64编码的key和iv
        key = base64.b64decode(key)
        iv = base64.b64decode(iv)

        # 创建解密器
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        # 解密密码
        decrypted_padded_password = decryptor.update(base64.b64decode(encrypted_password)) + decryptor.finalize()

        # 移除填充
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        decrypted_password = unpadder.update(decrypted_padded_password) + unpadder.finalize()

        return decrypted_password.decode('utf-8')
    except Exception as e:
        # 处理解密错误
        return "Decryption operation failed! Invalid IV or/and Key."

def encrypt_password(plain_password, key, iv):
    # 解码base64编码的key和iv
    key = base64.b64decode(key)
    iv = base64.b64decode(iv)

    # 创建加密器
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # 使用PKCS#7填充
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plain_password.encode()) + padder.finalize()

    # 加密密码
    encrypted_password = encryptor.update(padded_data) + encryptor.finalize()

    # 返回base64编码的加密密码
    return base64.b64encode(encrypted_password).decode('utf-8')

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    plain_password = data.get('password')

    if not username or not plain_password:
        return jsonify({"message": "Username and password are required"}), 400

    # Find the user
    user = User.query.filter_by(user_username=username).first()

    if user:
        # Join with the key table from another database
        user_key = UserKey.query.filter_by(key_id=user.user_salt).first()
        if not user_key:
            return jsonify({"message": "User key not found"}), 404

        # Split key_data into IV and KEY
        key_data = user_key.key_data.split(',')
        if len(key_data) != 2:
            return jsonify({"message": "Invalid key data format"}), 500

        iv, key = key_data

        # Encrypt the user's input password
        encrypted_password = encrypt_password(plain_password, key, iv)

        if encrypted_password == user.user_password:
            # Login successful, generate JWT token
            access_token = create_access_token(identity=user.user_id)
            return jsonify({"message": "Login successful", "user_id": user.user_id, "usersname": user.user_name, "access_token": access_token}), 200
        else:
            # Login failed
            return jsonify({"message": "Invalid username or password"}), 401
    else:
        # User not found
        return jsonify({"message": "Invalid username or password"}), 401

@app.route('/user/components', methods=['GET'])
@jwt_required()
def get_user_components(): 
    user_id = get_jwt_identity()
    if not user_id:
        return jsonify({"message": "User ID is required"}), 400

    try:
        # Get the user's roles, and assoc_expiry_date is not earlier than today
        today = datetime.utcnow().date()
        associations = UserRoleAssociation.query.filter(
            UserRoleAssociation.user_id == user_id,
            # UserRoleAssociation.assoc_expiry_date >= today
        ).all()

        # Get all component ids the user can access
        role_ids = [assoc.role_id for assoc in associations]
        application_ids = [assoc.application_id for assoc in associations]
        roles = Role.query.filter(Role.role_id.in_(role_ids)).all()
        component_ids = [role.component_id for role in roles]

        # Get component names, only return those with component_has_api as true
        components = SoftwareComponent.query.filter(
            SoftwareComponent.component_id.in_(component_ids),
            SoftwareComponent.component_has_api == True
        ).all()

        # Build the return result
        result = [{
            "component_id": component.component_id,
            "component_name": component.component_name,
            "component_desc": component.component_desc,
            "role_id": assoc.role_id,
            "application_id": assoc.application_id
        } for assoc in associations for component in components if component.component_id in component_ids]

        return jsonify(result), 200
    except Exception as e:
        return jsonify({"message": "Error fetching components", "error": str(e)}), 500

@app.route('/generate-pat', methods=['POST'])
@jwt_required()
def generate_pat():
    data = request.json
    user_id = data.get('user_id')
    application_id = data.get('application_id')
    role_id = data.get('role_id')

    if not user_id or not application_id or not role_id:
        return jsonify({"message": "User ID, Application ID, and Role ID are required"}), 400

    try:
        # Verify if the user has access to the specified component
        today = datetime.utcnow().date()
        association = UserRoleAssociation.query.filter_by(
            user_id=user_id,
            application_id=application_id,
            role_id=role_id
        ).first()

        if not association:
            return jsonify({"message": "Invalid access or expired association"}), 403

        # Get the user's salt as the key
        user = User.query.filter_by(user_id=user_id).first()
        if not user or not user.user_salt:
            return jsonify({"message": "User salt not found"}), 404

        # Ensure the key length is 16 bytes
        key = user.user_salt.encode()
        if len(key) < 16:
            key = key.ljust(16, b'\0')  # 使用空字节填充
        else:
            key = key[:16]  # 截取前16字节

        # Generate PAT
        pat = f"{user_id},{application_id},{role_id}"

        # Use PKCS#7 to pad the data
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(pat.encode()) + padder.finalize()

        # Generate random IV
        iv = os.urandom(16)

        # Encrypt PAT using the user's salt as the key and IV
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_pat = encryptor.update(padded_data) + encryptor.finalize()

        # Store the IV and encrypted PAT together
        encrypted_pat_with_iv = base64.b64encode(iv + encrypted_pat).decode('utf-8')
        association.assoc_api_token = encrypted_pat_with_iv
        db.session.commit()

        return jsonify({"pat": encrypted_pat_with_iv, "expires_at": association.assoc_expiry_date}), 200
    except Exception as e:
        return jsonify({"message": "Error generating PAT", "error": str(e)}), 500

@app.route('/user/pats', methods=['GET'])
@jwt_required()
def get_user_pats():
    user_id = request.args.get('user_id')
    if not user_id:
        return jsonify({"message": "User ID is required"}), 400

    try:
        # Query all PATs of the user
        associations = UserRoleAssociation.query.filter_by(user_id=user_id).all()

        # Get related application and component information
        application_ids = [assoc.application_id for assoc in associations]
        role_ids = [assoc.role_id for assoc in associations]

        applications = {app.application_id: app.application_name for app in Application.query.filter(Application.application_id.in_(application_ids)).all()}
        roles = Role.query.filter(Role.role_id.in_(role_ids)).all()
        component_ids = [role.component_id for role in roles]
        components = {comp.component_id: comp.component_name for comp in SoftwareComponent.query.filter(SoftwareComponent.component_id.in_(component_ids)).all()}

        # Build the return result
        result = [{
            "application_id": assoc.application_id,
            "application_name": applications.get(assoc.application_id, "Unknown"),
            "role_id": assoc.role_id,
            "component_name": components.get(next((role.component_id for role in roles if role.role_id == assoc.role_id), None), "Unknown"),
            "assoc_api_token": assoc.assoc_api_token,
            "assoc_expiry_date": assoc.assoc_expiry_date
        } for assoc in associations]

        return jsonify(result), 200
    except Exception as e:
        return jsonify({"message": "Error fetching PATs", "error": str(e)}), 500

# 提供的IV和KEY
iv = "dMiwubYfUrdb0Mn539BZXw=="
key = "1GBy755bP5nhjc6QWwjD8HGvPKDXGeiIuS5zbTjQipk="
encrypted_password = "W89lFB6TPKTe0iV5IOP3cA=="

# 解密
decrypted_password = decrypt_password(encrypted_password, key, iv)
print("Decrypted password:", decrypted_password)


if __name__ == '__main__':
    app.run(debug=True)

