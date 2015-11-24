from __future__ import print_function
from os.path import join, dirname, realpath
from Crypto.Random.random import randint
from getpass import getpass

DEFAULT_PASSWORD_LENGTH = 8

def make_password(len=DEFAULT_PASSWORD_LENGTH):
    password = []
    ids = list()
    for _ in xrange(0, len):
        ids.append(''.join(['%s' % randint(1, 6) for _ in xrange(0, 5)]))
    with open(join(dirname(realpath(__file__)), 'wordlist'), 'r') as word_list:
        for word in word_list:
            id, word = word.strip().split('\t')
            for an_id in ids:
                if id == an_id:
                    password.append(word)
                    ids.remove(an_id)
    return ' '.join(password)

def generate_password():
    while True:
        password = make_password()
        print('Your Master Password: %s' % password)
        confirm = raw_input('Press Y/y to accept or N/n to generate a new one: ').strip().lower()
        if len(confirm) < 1 or confirm[0] == 'y':
            password = password.split()
            return ( '-'.join(password[:4]), '-'.join(password[4:]) )

def prompt_password():
    password = None
    while True:
        password = getpass('Master Password: ').strip().split()
        if len(password) == DEFAULT_PASSWORD_LENGTH:
            break
        else:
            print('Invalid Password Length: Must be %s groups of words.' % DEFAULT_PASSWORD_LENGTH)
    return ( '-'.join(password[:4]), '-'.join(password[4:]) )

if __name__ == '__main__':
    print('Your Password:', generate_password())
    p1, p2 = prompt_password()
    print('Password 1: %s' % p1)
    print('Password 2: %s' % p2)