"""Translate catalog requests into authenticated native APIs of the local range."""
import hashlib
import json
from pathlib import Path

ROUTES = {'/record':'/api/records/read', '/export':'/api/exports', '/search':'/api/records/search',
          '/update':'/api/records/update', '/link':'/api/link', '/fetch':'/api/fetch',
          '/fulfill':'/api/orders/fulfill', '/protected':'/api/protected/read', '/chat':'/api/ai/chat'}

def validate_sessions(target):
    path = Path(target['sessions_file'])
    if path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o077:
        raise ValueError('Sessions must be a private regular file')
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != target['sessions_sha256']:
        raise ValueError('Sessions changed after campaign preparation')
    sessions = json.loads(raw)
    if set(sessions) != {'alice','admin'} or not all(isinstance(v,str) and v.startswith('lab-session-') for v in sessions.values()):
        raise ValueError('Only synthetic range sessions are supported')
    return sessions

def translate(target, req):
    sessions = validate_sessions(target)
    body, path = req['body'], req['path']
    identity = 'admin' if path == '/export' and body['role'] == 'admin' else 'alice'
    if path == '/record': native = {'owner':body['record']}
    elif path == '/search': native = {'term':body['term']}
    elif path == '/update': native = {k:v for k,v in body.items()}
    elif path == '/link': native = {'id_token':body['id_token']}
    elif path == '/fetch': native = {'url':body['url']}
    elif path == '/export': native = {}
    elif path == '/fulfill': native = {'order_id':'paid' if body['paid'] else 'unpaid'}
    elif path == '/protected': native = {'dependency':'available' if body['policy_available'] else 'offline'}
    elif path == '/chat': native = {k:v for k,v in body.items() if k != 'tenant'}
    else: raise ValueError('Unsupported native route')
    return {'method':'POST','path':ROUTES[path],'body':native}, {'Authorization':'Bearer '+sessions[identity]}
