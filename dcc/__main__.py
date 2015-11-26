from __future__ import print_function
from functools import partial
from sys import argv, exit
from os.path import join, splitext, normpath, basename
from os import urandom, getcwd
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from pbkdf2 import PBKDF2
from diceware import generate_password, prompt_password
from uuid import uuid4
from random import randint
import cPickle as pickle

#region VFS virtual file system utility methods

class VFSFileData(object):
    def __init__(self, path):
        self.name = basename(path)
        self.uuid = '%s' % uuid4()
    def __str__(self):
        return '%s (%s)' % (self.name, self.uuid)

def save_vfs(encryption_key, signing_key, vfs=dict()):
    vfs_data = pickle.dumps(vfs)
    with open(join(getcwd(), 'vfs'), 'w+') as vfs_file:
        vfs_file.write(encrypt(vfs_data, encryption_key, signing_key))

def load_vfs(encryption_key, signing_key):
    with open(join(getcwd(), 'vfs'), 'r') as vfs_file:
        return pickle.loads(decrypt(vfs_file.read(), encryption_key, signing_key))

def tree_vfs(component, indent=0):
    spacer = ''.join([' ' for _ in xrange(0, indent)])
    if type(component) == VFSFileData:
        print('%s%s' % (spacer, str(component)))
    else:
        for sub_component in component.iterkeys():
            print('%s%s/' % (spacer, sub_component))
            tree_vfs(component[sub_component], indent=indent + 4)

def get_vfs_file(virtual_fs, path):
    input_path = normpath(join('/', './%s' % path))[1:].split('/')
    str_path = '/'
    vfs_path = virtual_fs
    if not ( len(input_path) == 1 and input_path[0] == '' ):
        for component in input_path:
            str_path = '%s%s/' % ( str_path, component )
            try:
                vfs_path = vfs_path[component]
            except:
                return (True, str_path[1:], None)
    return (False, str_path[1:], vfs_path)

def vfs_register(virtual_fs, components, file_data):
    current = virtual_fs
    for component in components:
        if not current.has_key(component):
            current[component] = dict()
        current = current[component]
    current[file_data.name] = file_data

#endregion

#region dccfile makes a dcc file which tells this client the unique container name

# 6 random integers to reduce chances of conflicts for containers with the same name
def make_dccfile(encryption_key, signing_key):
    container_name = b64encode('%s%s' % (''.join([str(randint(1, 10)) for _ in xrange(0, 5)]), raw_input('Container Name: ').strip()[:50]))
    dropbox_token = raw_input('Dropbox API Token: ').strip()
    with open(join(getcwd(), '.dcc'), 'w+') as dcc_file:
        content = pickle.dumps(dict(cn=container_name, dbtk=dropbox_token))
        dcc_file.write(encrypt(content, encryption_key, signing_key))

# returns a 3-tuple ( human readable container name, file system container name, dropbox api token )
def get_dccinfo(encryption_key, signing_key):
    with open(join(getcwd(), '.dcc'), 'r') as dcc_file:
        data = pickle.loads(decrypt(dcc_file.read(), encryption_key, signing_key))
        return ( b64decode(data['cn'])[6:], data['cn'], data['dbtk'] )

#endregion

#region Crypto encrypt/decrypt with signature validation

def encrypt(content, encryption_key, signing_key):
    iv = urandom(16)
    cipher = AES.new(encryption_key, AES.MODE_CBC, iv)
    encrypted = '%s%s' % ( iv, cipher.encrypt(pad(content)) )
    hash = HMAC.new(signing_key, digestmod=SHA256)
    hash.update(encrypted)
    return '%s%s' % (hash.hexdigest(), encrypted)

def decrypt(content, encryption_key, signing_key):
    signature, contents = ( content[:64], content[64:] )
    hash = HMAC.new(signing_key, digestmod=SHA256)
    hash.update(contents)
    if signature != hash.hexdigest():
        raise Exception('Invalid Signature')
    iv, contents = ( contents[:16], contents[16:] )
    cipher = AES.new(encryption_key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(contents))

BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS) 
unpad = lambda s : s[0:-ord(s[-1])]

def make_key(password): # makes a 256-bit key, a 128-bit iv and a 64-bit password salt
  iv = urandom(16) # 128-bit
  salt = urandom(8) # 64-bit
  key = urandom(32) # 256-bit key
  cipher = AES.new(PBKDF2(password, salt).read(32), AES.MODE_CBC, iv)
  print('Key: %s' % b64encode(key))
  return '%s%s%s' % (salt, iv, cipher.encrypt(pad(key)))

def get_key(password, key_matter):
    salt = key_matter[:8]
    iv = key_matter[8:24]
    key = key_matter[24:]
    cipher = AES.new(PBKDF2(password, salt).read(32), AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(key))

def read_keys():
    master_password, signing_password = prompt_password()
    with open(join(getcwd(), 'passwd'), 'r') as password_file:
        password_data = pickle.loads(password_file.read())
        return ( get_key(master_password, password_data['encryption_key']), get_key(signing_password, password_data['signing_key']) )

#endregion

#region Commands all handlers for command line actions

def no_command(command, *argv, **kwargs):
    return 'Unknown command: %s' % command

def setup(*args, **kwargs):
    master_password, signing_password = generate_password()
    password_data = dict(
        encryption_key=make_key(master_password),
        signing_key=make_key(signing_password),
    )
    pickle.dump(password_data, open(join(getcwd(), 'passwd'), 'w+'))
    encryption_key, signing_key = get_key(master_password, password_data['encryption_key']), get_key(signing_password, password_data['signing_key'])
    save_vfs(encryption_key, signing_key)
    make_dccfile(encryption_key, signing_key)
    return 0

def list_keys(*args, **kwargs):
    encryption_key, signing_key = read_keys()
    print('Encryption Key:', b64encode(encryption_key))
    print('Signing Key:', b64encode(signing_key))
    return 0

def list_files(*args, **kwargs):
    path = args[0] if len(args) >= 1 else ''
    vfs_err, vfs_path, vfs_result = get_vfs_file(load_vfs(*read_keys()), path)
    if vfs_err or type(vfs_result) == VFSFileData:
        print('Error: Path `%s` does not exist or is a file.' % vfs_path)
        return 1
    for item in vfs_result.iterkeys():
        print( 'file' if type(item) == VFSFileData else 'dir ', str(item) )
    return 0

def tree(*args, **kwargs):
    tree_vfs(load_vfs(*read_keys()))
    return 0

def add_file(file_path, *args, **kwargs):
    cwd = getcwd()
    path = normpath(join(getcwd(), file_path))
    if path[:len(cwd)] != cwd:
        print('Error: Cannot add file outside of protected directory.')
        return 1
    encryption_key, signing_key = read_keys()
    vfs = load_vfs(encryption_key, signing_key)
    with open(path, 'r') as input_file:
        file_data = VFSFileData(path)
        vfs_register(vfs, path[len(cwd)+1:].split('/')[:-1], file_data)
        with open(join(getcwd(), file_data.uuid), 'w+') as output_file:
            output_file.write(encrypt(input_file.read(), encryption_key, signing_key))
            save_vfs(encryption_key, signing_key, vfs=vfs)
    return 0

def read_file(file_path, *args, **kwargs):
    encryption_key, signing_key = read_keys()
    output_name = args[0] if len(args) >= 1 else None
    vfs_err, vfs_path, vfs_result = get_vfs_file(load_vfs(encryption_key, signing_key), file_path)
    if vfs_err or type(vfs_result) != VFSFileData:
        print('Error: Path `%s` does not exist or is not a file.' % vfs_path)
        return 1
    if output_name is None:
        output_name = vfs_result.name
    with open(join(getcwd(), vfs_result.uuid), 'r') as input_file:
        with open(join(getcwd(), output_name), 'w+') as output_file:
            output_file.write(decrypt(input_file.read(), encryption_key, signing_key))
    return 0

def show_help():
    map(print, [
        'Dropbox Confidentiality Client v1\n',
        'Usage: $ dcc [command] <file>\n',
        'Commands:',
        '  init - creates a password file to encrypt and sign files',
        '  keys - prints the encryption and signing keys in base64',
        '  list - calls the list command on the virtual file system',
        '  tree - recursive call to list to show all files',
        '  add - encrypts, signs and uploads an existing file',
        '  read - decrypts an already encrypted and signed file',
        '  help - prints this help message',
    ])
    return 0

#endregion

if __name__ == '__main__':
    arg = 'help' if len(argv) < 2 else argv[1].strip()
    exit({
        'init': setup,
        'keys': list_keys,
        'list': list_files,
        'tree': tree,
        'add': add_file,
        'read': read_file,
        'help': show_help
    }.get(arg, partial(no_command, arg))(*argv[2:]))