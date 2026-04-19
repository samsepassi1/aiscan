# aiscan test fixture — should trigger AI-SEC-002 (Missing Authorization)
# DO NOT USE IN PRODUCTION

from flask import Flask, jsonify
from fastapi import FastAPI

app = Flask(__name__)
api = FastAPI()


# VULNERABLE 1: Flask admin route with no auth decorator
@app.route('/admin/users')
def admin_users():
    return jsonify([])


# VULNERABLE 2: Flask DELETE mutation with no auth
@app.route('/api/users/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    return jsonify({'deleted': user_id})


# VULNERABLE 3: Flask POST mutation on sensitive path
@app.post('/api/posts')
def create_post():
    return jsonify({'id': 1}), 201


# VULNERABLE 4: FastAPI user-specific data with no Depends
@api.get('/user/{user_id}/profile')
async def get_user_profile(user_id: int):
    return {'user_id': user_id}


# VULNERABLE 5: FastAPI admin endpoint
@api.delete('/admin/posts/{post_id}')
async def admin_delete_post(post_id: int):
    return {'deleted': post_id}


# SAFE 1: @login_required present — should NOT be flagged
@app.route('/admin/dashboard')
@login_required  # noqa: F821
def admin_dashboard():
    return jsonify({'status': 'ok'})


# SAFE 2: FastAPI Depends — should NOT be flagged
@api.get('/user/{user_id}/data')
async def get_user_data(user_id: int, current_user=Depends(get_current_user)):  # noqa: F821
    return {'user_id': user_id}


# SAFE 3: Public health endpoint — should NOT be flagged
@app.get('/health')
def health():
    return {'status': 'ok'}


# SAFE 4: Public read endpoint — should NOT be flagged
@app.get('/api/public/articles')
def list_articles():
    return jsonify([])
