from flask import Flask, request, jsonify
from datetime import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
from dotenv import load_dotenv
from cryptography.hazmat.primitives import padding
import base64

from extension import cors
from models import User, db, UserRoleAssociation, Role, SoftwareComponent, Application

load_dotenv()

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)
cors.init_app(app)

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"message": "Username and password are required"}), 400

    # 查找用户
    user = User.query.filter_by(user_username=username).first()

    if user and user.user_password == password:
        # 登录成功
        return jsonify({"message": "Login successful", "user_id": user.user_id, "usersname": user.user_name}), 200
    else:
        # 登录失败
        return jsonify({"message": "Invalid username or password "  }), 401

@app.route('/user/components', methods=['GET'])
def get_user_components():
    user_id = request.args.get('user_id')
    if not user_id:
        return jsonify({"message": "User ID is required"}), 400

    try:
        # 获取当前用户的角色，且assoc_expiry_date不早于今天
        today = datetime.utcnow().date()
        associations = UserRoleAssociation.query.filter(
            UserRoleAssociation.user_id == user_id,
            # UserRoleAssociation.assoc_expiry_date >= today
        ).all()

        # 获取用户可以访问的所有component id
        role_ids = [assoc.role_id for assoc in associations]
        application_ids = [assoc.application_id for assoc in associations]
        roles = Role.query.filter(Role.role_id.in_(role_ids)).all()
        component_ids = [role.component_id for role in roles]

        # 获取component name，只返回component_has_api为true的
        components = SoftwareComponent.query.filter(
            SoftwareComponent.component_id.in_(component_ids),
            SoftwareComponent.component_has_api == True
        ).all()

        # 构建返回结果
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
def generate_pat():
    data = request.json
    user_id = data.get('user_id')
    application_id = data.get('application_id')
    role_id = data.get('role_id')

    if not user_id or not application_id or not role_id:
        return jsonify({"message": "User ID, Application ID, and Role ID are required"}), 400

    try:
        # 验证用户是否有权访问指定的component
        today = datetime.utcnow().date()
        association = UserRoleAssociation.query.filter_by(
            user_id=user_id,
            application_id=application_id,
            role_id=role_id
        ).first()

        if not association:
            return jsonify({"message": "Invalid access or expired association"}), 403

        # 获取用户的salt作为密钥
        user = User.query.filter_by(user_id=user_id).first()
        if not user or not user.user_salt:
            return jsonify({"message": "User salt not found"}), 404

        # 确保密钥长度为16字节
        key = user.user_salt.encode()
        if len(key) < 16:
            key = key.ljust(16, b'\0')  # 使用空字节填充
        else:
            key = key[:16]  # 截取前16字节

        # 生成PAT
        pat = f"{user_id},{application_id},{role_id}"

        # 使用PKCS#7填充数据
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(pat.encode()) + padder.finalize()

        # 生成随机IV
        iv = os.urandom(16)

        # 使用用户的salt作为密钥和IV加密PAT
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_pat = encryptor.update(padded_data) + encryptor.finalize()

        # 将IV和加密后的PAT一起存储
        encrypted_pat_with_iv = base64.b64encode(iv + encrypted_pat).decode('utf-8')
        association.assoc_api_token = encrypted_pat_with_iv
        db.session.commit()

        return jsonify({"pat": encrypted_pat_with_iv, "expires_at": association.assoc_expiry_date}), 200
    except Exception as e:
        return jsonify({"message": "Error generating PAT", "error": str(e)}), 500

@app.route('/user/pats', methods=['GET'])
def get_user_pats():
    user_id = request.args.get('user_id')
    if not user_id:
        return jsonify({"message": "User ID is required"}), 400

    try:
        # 查询用户的所有PAT
        associations = UserRoleAssociation.query.filter_by(user_id=user_id).all()

        # 获取相关的应用程序和组件信息
        application_ids = [assoc.application_id for assoc in associations]
        role_ids = [assoc.role_id for assoc in associations]

        applications = {app.application_id: app.application_name for app in Application.query.filter(Application.application_id.in_(application_ids)).all()}
        roles = Role.query.filter(Role.role_id.in_(role_ids)).all()
        component_ids = [role.component_id for role in roles]
        components = {comp.component_id: comp.component_name for comp in SoftwareComponent.query.filter(SoftwareComponent.component_id.in_(component_ids)).all()}

        # 构建返回结果
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

if __name__ == '__main__':
    app.run(debug=True)

