from __future__ import print_function
from sys import argv
from os import getcwd, mkdir, urandom
from os.path import join, dirname, realpath
from sqlite3 import connect as db_connect
from getpass import getpass
from pbkdf2 import PBKDF2
from Crypto.Cipher import AES
from base64 import b64encode

lib_path = dirname(realpath(__file__))
sql_file = join(lib_path, 'setup.sql')

def setup_dcc_folder():
  dcc_path = join(getcwd(), '.dcc')
  try:
    mkdir(dcc_path, 0755)
  except:
    print('Failed to create .dcc folder')
  conn = db_connect(join(dcc_path, 'db'))
  with open(sql_file, 'r') as sql:
    data = sql.read()
    for k,v in make_keyinfo(*prompt_passwords()):
      data.replace('{{ %s }}' % k, v)
    print(data)
    conn.cursor().executescript(data)
  conn.commit()
  conn.close()

def prompt_passwords():
  return ( getpass('Master Password: '), getpass('Signing Password: ') )

def make_key(password, salt):
  iv = urandom(16) # 128-bit IV
  cipher = AES.new(PBKDF2(password, salt).read(32), AES.MODE_CBC, iv)
  return '%s%s'% ( b64encode(iv), b64encode(cipher.encrypt(urandom(32))) ) # 256-bit key made

def make_keyinfo(mp, sp):
  ek_salt = urandom(8) # 64-bit salts
  sk_salt = urandom(8)
  return {
    'MASTER_ENCRYPTION_KEY': make_key(mp, ek_salt),
    'MASTER_SIGNING_KEY': make_key(sp, sk_salt),
    'MASTER_ENCRYPTION_KEY_SALT': b64encode(ek_salt),
    'MASTER_SIGNING_KEY_SALT': b64encode(sk_salt)
  }
  

if __name__ == '__main__':
  setup_dcc_folder()