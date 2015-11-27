from __future__ import print_function
from functools import partial
from sys import argv, exit
from os.path import join, splitext, normpath, basename, isfile, exists
from os import urandom, getcwd, makedirs
from base64 import b64encode, b64decode
from diceware import generate_password, prompt_password
from encryption import encrypt, decrypt, make_key, get_key
from client import save_passwd, read_passwd, save_vfs, load_vfs, upload_file, download_file
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

def show_tree(*args, **kwargs):
    if '--help' in ''.join(args):
        map(print, [
            'About: This command outputs a tree view of the virtual file system.',
        ])
        return 1
    encryption_key, signing_key, api_token, human_container_name, container_name = prompt_userinfo()
    vfs = load_vfs(api_token, container_name, encryption_key, signing_key)
    vfs.print_tree()
    return 0

def show_list(*args, **kwargs):
    args_joined = ' '.join(args)
    if len(args) == 0 or '--help' in args_joined:
        map(print, [
            'About: This command interactively browses the virtual file system.',
            '',
            'Usage: $ dcc list <path> (--no-interactive)',
            '',
            'Use `--no-interactive` to output specified path. Path must be provided and in the virtual file system.',
            'If using interactive mode specify `:q` to quit the interactivivity loop.'
        ])
        return 1
    encryption_key, signing_key, api_token, human_container_name, container_name = prompt_userinfo()
    vfs = load_vfs(api_token, container_name, encryption_key, signing_key)
    path = args[0].strip()
    while True:
        vfs.print_list_files(path)
        if '--no-interactive' in args_joined:
            break
        else:
            path = raw_input('> ').strip()
            if path == ':q':
                break
    return 0

def add_file(*args, **kwargs):
    if len(args) == 0 or '--help' in ''.join(args):
        map(print, [
            'About: This command adds a file to Dropbox by encrypting and signing the file using your private key.',
            '',
            'Usage: $ dcc add <path,...>',
            '',
            'Specify one or more paths delimited by spaces. Paths to files can be absolute or relative but must',
            'point to a file. Paths can refer to files outside of this directory.',
        ])
        return 1
    encryption_key, signing_key, api_token, human_container_name, container_name = prompt_userinfo()
    vfs = load_vfs(api_token, container_name, encryption_key, signing_key)
    for arg in args:
        if len(arg) > 0:
            full_path = normpath(join(getcwd(), arg))
            if isfile(full_path):
                with open(full_path, 'r') as source_file:
                    file_uuid = vfs.add_file(full_path)
                    upload_file(api_token, container_name, encrypt(source_file.read(), encryption_key, signing_key), file_uuid)
                    print('[DONE] `%s` ~> `%s`' % (full_path, file_uuid))
    save_vfs(api_token, container_name, vfs, encryption_key, signing_key)
    return 0

def get_file(*args, **kwargs):
    if len(args) == 0 or '--help' in ''.join(args):
        map(print, [
            'About: This command retrieves a file from the virtual file system if it exists.',
            '',
            'Usage: $ dcc get <virtual path> (<local path>)',
            '',
            'By default this will output the contents of the file to standard output unless the `<local path>` is specified.',
            'The `<local path>` can optionally include the filename otherwise the name of the file when uploaded will be used.'
        ])
        return 1
    encryption_key, signing_key, api_token, human_container_name, container_name = prompt_userinfo()
    vfs = load_vfs(api_token, container_name, encryption_key, signing_key)
    vfs_exists, data = vfs.get_file_data(args[0])
    if not vfs_exists:
        print('Error: The path `%s` does not exist.' % args[0])
        return 1
    if len(args) >= 2: # if we have virtual path and local path
        local_path = normpath(join(getcwd(), args[1].strip()))
        if len(local_path) > 0:
            local_filename = basename(local_path)
            if len(local_filename) > 0 and '.' not in local_filename:
                local_filename = ''
            if len(local_filename) > 0:
                local_path = local_path[:-len(local_filename)]
            else:
                local_filename = data[0]
            if not exists(local_path):
                makedirs(local_path)
            with open(join(local_path, local_filename), 'w+') as output_file:
                content = download_file(api_token, container_name, data[2])
                output_file.write(decrypt(content, encryption_key, signing_key))
                return 0
    # else we do not have the local path, we need to output to standard out
    content = download_file(api_token, container_name, data[2])
    print(decrypt(content, encryption_key, signing_key))
    return 0

def sync_files(*args, **kwargs):
    encryption_key, signing_key, api_token, human_container_name, container_name = prompt_userinfo()
    vfs = load_vfs(api_token, container_name, encryption_key, signing_key)
    for _, (file_name, path, file_uuid) in vfs.files.iteritems():
        path = path[:-len(basename(path))]
        print('Attempting to write `%s` ~> `%s`' % (file_name, path))
        if not exists(path):
            makedirs(path)
            print('  [OK] Created Path `%s`' % path)
        decrypted_file = decrypt(download_file(api_token, container_name, file_uuid), encryption_key, signing_key)
        print(' [OK] Downloaded and decrypted `%s`' % file_uuid)
        with open(join(path, file_name), 'w+') as output_file:
            output_file.write(decrypted_file)
            print(' [OK] Wrote file `%s`' % file_name)
    return 0

def show_help():
    map(print, [
        'Dropbox Confidentiality Client v1\n',
        'Usage: $ dcc [command] (<path,...>)\n',
        'Commands:',
        '  init - creates password, virtual file system and info files',
        '  info - shows the keys, token, container name and file count',
        '  tree - displays a tree of the virtual file system',
        '  list - interactively browse the virtual file system', 
        '  add - adds a new file to the virtual file system and uploads',
        '  get - downloads an uploaded file to existing/specific location',
        '  sync - downloads all uploaded files to the local file system',
        '  help - shows this help message',
        'For detailed command usage append `--help`',
        '',
        '[!] IMPORTANT',
        'You must setup a Dropbox API Token first. Read this blog post:',
        'https://blogs.dropbox.com/developers/2014/05/generate-an-access-token-for-your-own-account/',
        ''
    ])
    return 0

#endregion

if __name__ == '__main__':
    arg = 'help' if len(argv) < 2 else argv[1].strip()
    exit({
        'init': setup,
        'info': show_info,
        'tree': show_tree,
        'list': show_list,
        'add': add_file,
        'get': get_file,
        'sync': sync_files,
        'help': show_help,
    }.get(arg, partial(no_command, arg))(*argv[2:]))