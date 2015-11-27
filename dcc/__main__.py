from __future__ import print_function
from functools import partial
from sys import argv, exit
from os.path import join, splitext, normpath, basename
from os import urandom, getcwd
from base64 import b64encode, b64decode
from diceware import generate_password, prompt_password
from encryption import encrypt, decrypt, make_key, get_key
from client import save_passwd, read_passwd, save_vfs, load_vfs
from uuid import uuid4
from random import randint
import cPickle as pickle
from pbkdf2 import PBKDF2
from vfs import VFS

#region utils methods to support the commands below

# 6 random integers to reduce chances of conflicts for containers with the same name
# this file is encrypted using a key derived from PBKDF2 on the password NOT with the
# random encryption key generated later. This is because we want to maintain some
# form of security on the dropbox API token and integrity for the user provided data.
# returns a 2-tuple with ( file system container name, dropbox api token )
def make_dccfile(master_password, signing_password):
    container_name = b64encode('%s%s' % (''.join([str(randint(1, 10)) for _ in xrange(0, 5)]), raw_input('Container Name: ').strip()[:50]))
    dropbox_token = raw_input('Dropbox API Token: ').strip()
    with open(join(getcwd(), '.dcc'), 'w+') as dcc_file:
        salt_1, salt_2 = urandom(8), urandom(8)
        encryption_key, signing_key = PBKDF2(master_password, salt_1).read(32), PBKDF2(signing_password, salt_2).read(32)
        encrypted_content = encrypt(pickle.dumps(dict(cn=container_name, dbtk=dropbox_token)), encryption_key, signing_key)
        dcc_file.write('%s%s%s' % ( salt_1, salt_2, encrypted_content ))
        return ( container_name, dropbox_token )

# must prompt the user for the master password and signing password before calling which is used to decrypt the dcc file.
# returns a 3-tuple ( human readable container name, file system container name, dropbox api token )
def get_dccinfo(master_password, signing_password):
    with open(join(getcwd(), '.dcc'), 'r') as dcc_file:
        dcc_file = dcc_file.read()
        salt_1, salt_2, encrypted_data = ( dcc_file[:8], dcc_file[8:16], dcc_file[16:] )
        data = pickle.loads(decrypt(encrypted_data, PBKDF2(master_password, salt_1).read(32), PBKDF2(signing_password, salt_2).read(32)))
        return ( b64decode(data['cn'])[6:], data['cn'], data['dbtk'] )

# prompts the user for the master and singing password to verify and decrypt both the dcc file and passwd file (uploaded to Dropbox)
# returns a 5-tuple ( encryption key, signing key, dropbox api token, human readable container name, file system container name )
def prompt_userinfo():
    master_password, signing_password = prompt_password()
    human_container_name, fs_container_name, api_token = get_dccinfo(master_password, signing_password)
    password_data = read_passwd(api_token, fs_container_name, signing_password)
    return ( get_key(master_password, password_data['encryption_key']), get_key(signing_password, password_data['signing_key']), api_token, human_container_name, fs_container_name )

#endregion

#region Commands all handlers for command line actions

def no_command(command, *argv, **kwargs):
    return 'Unknown command: %s' % command

def setup(*args, **kwargs):
    master_password, signing_password = generate_password()
    password_data = dict( encryption_key=make_key(master_password), signing_key=make_key(signing_password) )
    container_name, api_token = make_dccfile(master_password, signing_password)
    save_passwd(api_token, container_name, password_data, signing_password)
    save_vfs(api_token, container_name, VFS(), get_key(master_password, password_data['encryption_key']), get_key(signing_password, password_data['signing_key']))
    return 0

def show_info(*args, **kwargs):
    encryption_key, signing_key, api_token, human_container_name, container_name = prompt_userinfo()
    vfs = load_vfs(api_token, container_name, encryption_key, signing_key)
    print('Encryption Key:', b64encode(encryption_key))
    print('Signing Key:', b64encode(signing_key))
    print('API Token:', api_token)
    print('Container Name:', '%s (%s)' % ( human_container_name, container_name ))
    print('File Count:', len(vfs))
    return 0

def add_file(*args, **kwargs):
    return 0

def read_file(*args, **kwargs):
    return 0

def sync_files(*args, **kwargs):
    return 0

def show_help():
    map(print, [
        'Dropbox Confidentiality Client v1\n',
        'Usage: $ dcc [command] <file>\n',
        'Commands:',
        '  init - creates password, virtual file system and info files',
        '  info - shows the keys, token, container name and file count',
        '  help - shows this help message',
    ])
    return 0

#endregion

if __name__ == '__main__':
    arg = 'help' if len(argv) < 2 else argv[1].strip()
    exit({
        'init': setup,
        'info': show_info,
        'help': show_help,
    }.get(arg, partial(no_command, arg))(*argv[2:]))