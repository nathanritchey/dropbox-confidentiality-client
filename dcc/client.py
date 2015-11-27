from __future__ import print_function

import urllib3.contrib.pyopenssl
urllib3.contrib.pyopenssl.inject_into_urllib3()

from encryption import encrypt, decrypt
from Crypto.Hash import HMAC, SHA256

import dropbox
from dropbox.files import WriteMode
from dropbox.exceptions import ApiError, AuthError
from contextlib import closing
import cPickle as pickle
import time

def write_file(db_client, content, container, file_name):
    try:
        res = db_client.files_upload(content, '/%s/%s' % (container, file_name), mode=WriteMode('overwrite'))
        return True
    except ApiError as err:
        if (err.error.is_path() and err.error.get_path().error.is_insufficient_space()):
            print('Upload Error: Insufficient Space')
        if err.user_message_text:
            print('Dropbox Message: %s' % err.user_message_text)
        return False

def read_file(db_client, container, file_name):
    try:
        meta, response = db_client.files_download('/%s/%s' % (container, file_name))
        with closing(response) as page:
            return (True, meta, page.content)
    except:
        return (False, None, None)

def upload_file(api_token, container_name, file_contents, file_uuid):
    return write_file(dropbox.Dropbox(api_token), file_contents, container_name, file_uuid)

def download_file(api_token, container_name, file_uuid):
    _, _, data = read_file(dropbox.Dropbox(api_token), container_name, file_uuid)
    return data

def save_vfs(api_token, container_name, vfs_instance, encryption_key, signing_key):
    db_client = dropbox.Dropbox(api_token)
    content = encrypt(pickle.dumps(vfs_instance), encryption_key, signing_key)
    write_file(db_client, content, container_name, 'vfs')

def load_vfs(api_token, container_name, encryption_key, signing_key):
    db_client = dropbox.Dropbox(api_token)
    _, _, encrypted = read_file(db_client, container_name, 'vfs')
    return pickle.loads(decrypt(encrypted, encryption_key, signing_key))

def save_passwd(api_token, container_name, password_data, signing_password):
    db_client = dropbox.Dropbox(api_token)
    password_data = pickle.dumps(password_data)
    hash = HMAC.new(signing_password, digestmod=SHA256)
    hash.update(password_data)
    return write_file(db_client, '%s%s' % ( hash.hexdigest(), password_data ), container_name, 'passwd')

def read_passwd(api_token, container_name, signing_password):
    db_client = dropbox.Dropbox(api_token)
    _, _, passwd_raw = read_file(db_client, container_name, 'passwd')
    signature, password_data = passwd_raw[:64], passwd_raw[64:]
    hash = HMAC.new(signing_password, digestmod=SHA256)
    hash.update(password_data)
    if signature != hash.hexdigest():
        raise Exception('Invalid Signature')
    return pickle.loads(password_data)
 