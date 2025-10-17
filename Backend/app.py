from flask import Flask, request, jsonify
from datetime import datetime, timedelta, UTC
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
        # Decode the base64 encoded key and iv
        key = base64.b64decode(key)
        iv = base64.b64decode(iv)

        # Create a decryptor
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        # Decrypt the password
        decrypted_padded_password = decryptor.update(base64.b64decode(encrypted_password)) + decryptor.finalize()

        # Remove padding
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        decrypted_password = unpadder.update(decrypted_padded_password) + unpadder.finalize()

        return decrypted_password.decode('utf-8')
    except Exception as e:
        # Handle decryption errors
        return "Decryption operation failed! Invalid IV or/and Key."

def encrypt_password(plain_password, key, iv):
    # Decode the base64 encoded key and iv
    key = base64.b64decode(key)
    iv = base64.b64decode(iv)

    # Create an encryptor
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Use PKCS#7 padding
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plain_password.encode()) + padder.finalize()

    # Encrypt the password
    encrypted_password = encryptor.update(padded_data) + encryptor.finalize()

    # Return the base64 encoded encrypted password
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
        if user.user_is_disabled:
            return jsonify({"message": "User is disabled"}), 403
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
            access_token = create_access_token(identity=user.user_id)
            # check if user needs to change new password
            if user.user_password_change_date and user.user_password_change_date <= datetime.utcnow().date():
                return jsonify({"message": "Password change required", "user_id": user.user_id, "usersname": user.user_name,"access_token": access_token}), 403  # 或者 401，并附带一个标识

            # Login successful, generate JWT token

            return jsonify({"message": "Login successful", "user_id": user.user_id, "usersname": user.user_name, "access_token": access_token,"IV": iv, "KEY": key}), 200
        else:
            # Login failed
            return jsonify({"message": "Invalid username or password"}), 401
    else:
        # User not found
        return jsonify({"message": "Invalid username or password"}), 401


@app.route('/change-password', methods=['POST'])
@jwt_required()
def change_password():
    data = request.json
    old_password = data.get('old_password')
    new_password = data.get('new_password')

    if not old_password or not new_password:
        return jsonify({"message": "Old password and new password are required"}), 400

    current_user_id = get_jwt_identity() # 获取当前登录用户的 ID

    user = User.query.get(current_user_id)
    if not user:
        return jsonify({"message": "User not found"}), 404

    # 1. 验证旧密码
    user_key = UserKey.query.filter_by(key_id=user.user_salt).first()
    if not user_key:
        return jsonify({"message": "User key not found"}), 500 # 或者更具体的错误信息

    key_data = user_key.key_data.split(',')
    if len(key_data) != 2:
        return jsonify({"message": "Invalid key data format"}), 500
    iv, key = key_data

    encrypted_old_password = encrypt_password(old_password, key, iv)

    if encrypted_old_password != user.user_password:
        return jsonify({"message": "Invalid old password"}), 401
    if old_password == new_password:
        return jsonify({"message": "New password cannot be the same as the old password"}), 400  # 使用 400 Bad Request

    # 2. 加密新密码
    encrypted_new_password = encrypt_password(new_password, key, iv)

    # 3. 更新用户密码
    user.user_password = encrypted_new_password

    # 4. 更新 user_password_change_date 到六个月后
    from datetime import datetime, timedelta
    user.user_password_change_date = datetime.now(UTC) + timedelta(days=180) # 假设180天为六个月

    try:
        db.session.commit() # 提交数据库更改
        return jsonify({"message": "Password changed successfully"}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"message": "Error changing password", "error": str(e)}), 500

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
            UserRoleAssociation.assoc_expiry_date >= today
        ).all()

        # Get all component ids the user can access
        role_ids = [assoc.role_id for assoc in associations]
        roles = Role.query.filter(Role.role_id.in_(role_ids)).all()
        component_ids = [role.component_id for role in roles]

        # 获取所有符合条件的 SoftwareComponent 对象，它们必须在 component_ids 中且 component_has_api 为 True
        valid_components = {
            c.component_id: c
            for c in SoftwareComponent.query.filter(
                SoftwareComponent.component_id.in_(component_ids),
                SoftwareComponent.component_has_api == True
            ).all()
        }
        result = []
        for assoc in associations:
            # 找到当前 assoc 对应的 role
            related_role = next((r for r in roles if r.role_id == assoc.role_id), None)
            if related_role:
                component_id_from_role = related_role.component_id
                # 检查这个 component_id 是否在 valid_components 中 (即它有API)
                if component_id_from_role in valid_components:
                    component = valid_components[component_id_from_role]
                    result.append({
                        "component_id": component.component_id,
                        "component_name": component.component_name,
                        "component_desc": component.component_desc,
                        "role_id": assoc.role_id, # 从当前 assoc 获取
                        "application_id": assoc.application_id # 从当前 assoc 获取
                    })

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
        association = UserRoleAssociation.query.filter_by(
            user_id=user_id,
            application_id=application_id,
            role_id=role_id
        ).first()

        if not association:
            return jsonify({"message": "Invalid access or expired association"}), 403

        user = User.query.filter_by(user_id=user_id).first()
        if not user or not user.user_salt:
            return jsonify({"message": "User salt not found"}), 404

        user_key = UserKey.query.filter_by(key_id=user.user_salt).first()
        if not user_key:
            return jsonify({"message": "User key not found"}), 404

        key_data = user_key.key_data.split(',')
        if len(key_data) != 2:
            return jsonify({"message": "Invalid key data format"}), 500

        iv, key = key_data  # Use the IV obtained during login
        iv = base64.b64decode(iv)
        key = base64.b64decode(key)
    

        # Generate PAT with current timestamp
        current_time = datetime.utcnow().isoformat()
        pat = f"{user_id},{application_id},{role_id},{current_time}"

        # Use PKCS#7 to pad the data
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(pat.encode()) + padder.finalize()

        # Encrypt PAT using the user's salt as the key and the fetched IV
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_pat = encryptor.update(padded_data) + encryptor.finalize()

        # Store the encrypted PAT
        encrypted_pat_with_iv = base64.b64encode(encrypted_pat).decode('utf-8')
        association.assoc_api_token = encrypted_pat_with_iv
        db.session.commit()

        return jsonify({"pat": encrypted_pat_with_iv, "expires_at": association.assoc_expiry_date}), 200
    except Exception as e:
        return jsonify({"message": "Error generating PAT", "error": str(e)}), 500

@app.route('/user/pats', methods=['GET'])
@jwt_required()
def get_user_pats():
    global expiry_date_display
    user_id = request.args.get('user_id')
    if not user_id:
        return jsonify({"message": "User ID is required"}), 400

    try:
        # Query all PATs of the user, filtering out those with null assoc_api_token
        associations = UserRoleAssociation.query.filter_by(user_id=user_id).filter(UserRoleAssociation.assoc_api_token.isnot(None)).all()

        # Get related application and component information
        application_ids = [assoc.application_id for assoc in associations]
        role_ids = [assoc.role_id for assoc in associations]

        applications = {app.application_id: app.application_name for app in Application.query.filter(Application.application_id.in_(application_ids)).all()}
        roles = Role.query.filter(Role.role_id.in_(role_ids)).all()
        component_ids = [role.component_id for role in roles]
        components = {comp.component_id: comp.component_name for comp in SoftwareComponent.query.filter(SoftwareComponent.component_id.in_(component_ids)).all()}

        # Build the return result
        result = []
        for assoc in associations:
            creation_date_only = assoc.assoc_creation_time.date() if hasattr(assoc.assoc_creation_time, 'date') else assoc.assoc_creation_time
            expiry_date_only = assoc.assoc_expiry_date.date() if hasattr(assoc.assoc_expiry_date, 'date') else assoc.assoc_expiry_date

            expiry_date_display = ""
            if creation_date_only == expiry_date_only:
                expiry_date_display = "Permanent Valid"
            else:
                expiry_date_display = assoc.assoc_expiry_date + timedelta(days=1)

        result.append({
            "application_id": assoc.application_id,
            "application_name": applications.get(assoc.application_id, "Unknown"),
            "role_id": assoc.role_id,
            "component_name": components.get(
                next((role.component_id for role in roles if role.role_id == assoc.role_id), None), "Unknown"),
            "assoc_api_token": assoc.assoc_api_token,
            "assoc_expiry_date": expiry_date_display
        })

        return jsonify(result), 200
    except Exception as e:
        return jsonify({"message": "Error fetching PATs", "error": str(e)}), 500

def decrypt_pat(encrypted_pat, key, iv):
    try:
        # Decode the base64 encoded key and iv
        key = base64.b64decode(key)
        iv = base64.b64decode(iv)

        # Create a decryptor
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        # Decrypt the PAT
        decrypted_padded_pat = decryptor.update(base64.b64decode(encrypted_pat)) + decryptor.finalize()

        # Remove padding
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        decrypted_pat = unpadder.update(decrypted_padded_pat) + unpadder.finalize()

        return decrypted_pat.decode('utf-8')
    except Exception as e:
        # Handle decryption errors
        return "Decryption operation failed! Invalid IV or/and Key."+str(e)

@app.route('/decrypt-pat', methods=['POST'])
def decrypt_pat_api():
    data = request.json
    username = data.get('username')
    encrypted_pat = data.get('pat')

    if not username or not encrypted_pat:
        return jsonify({
            "valid": False,
            "msg": "Username and PAT are required",
            "data": {}
        }), 400

    try:
        # 1. 获取用户和密钥信息
        user = User.query.filter_by(user_username=username).first()
        if not user or not user.user_salt:
            return jsonify({
                "valid": False,
                "msg": "User not found or user salt missing",
                "data": {}
            }), 404

        user_key = UserKey.query.filter_by(key_id=user.user_salt).first()
        if not user_key:
            return jsonify({
                "valid": False,
                "msg": "User key not found",
                "data": {}
            }), 404

        # 2. 解密 PAT
        key_data = user_key.key_data.split(',')
        if len(key_data) != 2:
            return jsonify({
                "valid": False,
                "msg": "Invalid key data format",
                "data": {}
            }), 500

        iv, key = key_data
        decrypted_pat = decrypt_pat(encrypted_pat, key, iv)
        
        if "Decryption operation failed" in decrypted_pat:
            return jsonify({
                "valid": False,
                "msg": "Decryption failed",
                "data": {}
            }), 500

        # 3. 解析解密后的数据 - 关键修改：去除所有空格
        try:
            pat_parts = decrypted_pat.split(',')
            if len(pat_parts) != 4:
                return jsonify({
                    "valid": False,
                    "msg": "Invalid PAT format",
                    "data": {}
                }), 400

            # 去除所有空格
            user_id = pat_parts[0].strip()
            application_id = pat_parts[1].strip()
            role_id = pat_parts[2].strip()
            time_created = pat_parts[3].strip() 
                
        except ValueError:
            return jsonify({
                "valid": False,
                "msg": "Invalid PAT data format",
                "data": {}
            }), 400

        # 4. 验证用户存在性
        target_user = User.query.filter_by(user_id=user_id).first()
        if not target_user:
            return jsonify({
                "valid": False,
                "msg": "User ID not found in database",
                "data": {}
            }), 404

        # 5. 验证访问权限
        association = UserRoleAssociation.query.filter_by(
            user_id=user_id,
            application_id=application_id,
            role_id=role_id
        ).first()

        if not association:
            return jsonify({
                "valid": False,
                "msg": "User does not have access rights to the target application with the specified role",
                "data": {}
            }), 403

        # 6. 返回成功响应
        return jsonify({
            "valid": True,
            "msg": "success",
            "data": {
                "user_id": user_id,
                "application_id": application_id,
                "role_id": role_id,
                "time_created": time_created
            }
        }), 200

    except Exception as e:
        return jsonify({
            "valid": False,
            "msg": f"Error processing request: {str(e)}",
            "data": {}
        }), 500

print(decrypt_pat("WLAcbHpl7kygG5nGZ0iZlGELhs/eH4ZIlZPhgmlmG25kFiPzvpqiC2ULyxlAT99A+ReFjmaGcrhT5TMMZUs5U4SePNdZmYliQ9hsjv2jS8rrwcrIZl2vEVR7vsn79q89jWHc6jl6SQWzysIV8y0tjqrj0jP8EI7VNtk0ta59VAiTpz8INFEKuSMkFySi0JBvBjyKQCGUpGk8SOPvi3+VjaVxEYX/SaWRRtUf0G+Ux7E=", "29m6wMU4sMMIFwEiMkQcxgSNQDic2c/nCgqKaSUDcQU=", "vYeUCDeebSzE9yWaFNN1Pw=="))
print(decrypt_pat("l9EjqE42faSnYqbH3q3lUpumJfhxPd1H1XNNSXS2blUGYNk/82B3xphQ5Diex0EDjjICLPy4gYuL1lUcCHSUnW+IObH0fOgUEaFqWagSqJYVBST3ATfoH+L4qVJT4wMfQndr/+AWyQnkLRveAibcILwMTcl2Pff41b1D8u13FfDJbu9ktnlk9uuV9eC22ya+AQH7eQ+EQOzlvzZR1uORajTOo/mL83+UO0wXqjlrxps=", "CrwTLO1dxsHCC+srmwsjWwiwxtAq7me8F0o7H1i6nz4=", "t3NnCpnDsv7sl3c1f5f7Vw=="))
print(decrypt_pat("iha9/sadpqA6C1wuPKA5KggYvMvcID+CvpsMJMvxwr7PJF5vO7aM0Ntjjc1d/5aE+CjLJIjdF0GmHR828SRdApmnFJTk/m9gKBYPKYZyas8WoOwIQVLes2W3hMmYBpm2GiWyuyLs8AE4xlRhfrBzoBSx2ZeyCSuwe47wuIYvS3FFALMorbi8iPmMw1T1+hHv6ed4phC1+0Gpse6RfXctiCpfGQI8New1urpnPxyGmj4=", "1GBy755bP5nhjc6QWwjD8HGvPKDXGeiIuS5zbTjQipk=", "dMiwubYfUrdb0Mn539BZXw=="))

if __name__ == '__main__':
    app.run(debug=True)

