from __future__ import print_function

import urllib3.contrib.pyopenssl
urllib3.contrib.pyopenssl.inject_into_urllib3()

from encryption import encrypt, decrypt

import dropbox
from dropbox.files import WriteMode
from dropbox.exceptions import ApiError, AuthError
from contextlib import closing
import cPickle as pickle
import time

def write_file(db_client, content, container, file_name):
    try:
        res = db_client.files_upload('/%s/%s' % (container, file_name), mode=WriteMode('overwrite'))
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

def save_vfs(api_token, container_name, vfs_instance, encryption_key, signing_key):
    db_client = dropbox.Dropbox(api_token)
    content = encrypt(pickle.dumps(vfs_instance), encryption_key, signing_key)
    write_file(db_client, content, container_name, 'vfs')

def load_vfs(api_token, container_name, encryption_key, signing_key):
    db_client = dropbox.Dropbox(api_token)
    encrypted = read_file(db_client, container_name, 'vfs')
    return pickle.loads(decrypt(encrypted, encryption_key, signing_key))

# performs an atomic operation that requires a lock file. If a lock file is present then it will wait.
# configuration of wait is sliding scale it will first wait long, then short repeating short waits.
# returns ( True/False if operation was called, result of operation if called else error message )
#def atomic_operation(db_client, container_name, signing_key, operation):
#    try:
#        _, res = db_client.files_download('/%s/Lock' % container_name)
#        with closing(res) as page:
#            return (False, 'Lock file is active.')
#    except ApiError as err:
#        if err.error.is_path():
#            try:
#                res = db_client.files_upload('LOCK', '/%s/Lock' % container_name)
#            except ApiError as err:
#                if (err.error.is_path() and err.error.get_path().error.is_insufficient_space()):
#                    return (False, 'Insufficient space to write Lock file.')
#                else:
#                    return (False, err.user_message_text if err.user_message_text else None)
#        else:
#            return (False, err.user_message_text if err.user_message_text else None)
#        
#if __name__ == '__main__':
    #api_token = 'wpm4Hp2-KfcAAAAAAAAa9EJMM8uYccGKUoWSZMGN7IgOZ1rIm5I62IMjDjZKA1zE'
    #db_client = dropbox.Dropbox(api_token)
    #atomic_operation(db_client, 'container-1', None)
# loads the vfs file from Dropbox to some local path
#def load_vfs_remote(db_client, local_path):
#    pass
# saves the vfs file from the local path to Dropbox
#def save_vfs_remote(db_client, vfs_data):
#    pass
#class DropboxInterface(object):
#
#    def __init__(self, api_token):
#        self.api_token = api_token
#        self.db_client = dropbox.Dropbox(self.api_token)
#
#
#
#
#
#
#
#
    #print 'linked account: ', db_client.users_get_current_account()
    #response = db_client.files_upload('hello, world!1', '/test.txt')
    #print('uploaded:', response)
    #for entry in db_client.files_list_folder('').entries:
    #    print(entry.name)
    #    print(entry)