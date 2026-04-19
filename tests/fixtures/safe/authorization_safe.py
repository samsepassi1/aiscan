# aiscan test fixture — should NOT trigger AI-SEC-002
# Demonstrates properly authorized route handlers

from flask import Flask, jsonify
from flask_login import login_required, current_user
from fastapi import FastAPI, Depends, HTTPException

app = Flask(__name__)
api = FastAPI()


async def get_current_user(token: str = Depends(oauth2_scheme)):  # noqa: F821
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return token


# Flask: decorator-based auth
@app.route('/admin/users')
@login_required
def admin_users():
    return jsonify([])


@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        return jsonify({'error': 'Forbidden'}), 403
    return jsonify({'deleted': user_id})


# FastAPI: Depends-based auth
@api.get('/user/{user_id}/profile')
async def get_user_profile(user_id: int, current_user=Depends(get_current_user)):
    return {'user_id': user_id}


@api.delete('/admin/posts/{post_id}')
async def admin_delete_post(post_id: int, current_user=Depends(get_current_user)):
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Admin required")
    return {'deleted': post_id}


# Public endpoints — correctly have no auth
@app.get('/health')
def health():
    return {'status': 'ok'}


@app.get('/api/public/articles')
def list_articles():
    return jsonify([])
