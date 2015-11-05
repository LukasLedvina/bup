#!/usr/bin/env python
import sys, stat, time, math

from bup import options, git
from bup.helpers import *

from shutil import copyfile, move
from filecmp import cmp

import datetime
import time

from hashlib import md5
from Crypto.Cipher import AES
from Crypto import Random
#
# FIXME
#   push, pull separate files
#   push to separate remotes (not only default)
#   enable ssh
#   cross files checksum
######
#   after password change, bup --repair must bu run
#   check password change
#

optspec = """
bup encrypt [-pcd --repair] [-k key] [-d decrypt-dir] [-e encrypt-dir] <files ...>
--
e,encrypt=      path to remote dir
d,decrypt=      path to local dir
k,key=          encryption key
p,push          push to remote directory
c,check         check remote backup
f,full          check content instead of modified  (takes a long time)
repair          repair remote (takes a long time)
"""

#nokey           without encryption (not implemented

def _sync_dirs(_dir, _dest):
    """Synchronize directory structure from local to remote dir.
    It should be run before any writing to remote dir.
    Using rsync. 
    Exits on fail.

    _dir   local backup
    _dest  remote encrypted backup
    """
    print "Synchonizing dirs\t",
    cmd = 'rsync -qa -f"+ */" -f"- *" '+_dir+" "+_dest
    ret1 = os.system(cmd)
    cmd = 'rsync -qa -f"+ */" -f"- *" '+_dir+" "+_dest+"/deleted"
    ret2 = os.system(cmd)
    if ret1 == 0 and ret2 == 0:
        print "[OK]"
    else:
        print "[failed] " + str(ret)
        exit(1)
    return 0

def _get_diff(
        _dir,
        _dest, 
        cmp_hash=False,
        hash_name="default"):
    """Compares hashes/timestamps in local backup with local hash-list
    return list of files to push and orphans in remote dir

    _dir       local backup
    _dest      remote encrypted backup
    cmp_hash   compare files using hash
    hash_name  hash-list name for multiple remotes (not implemented yet)
    """
    print "Calculating diff"
    hash_list = "encrypt/" + hash_name + ".sha1"
    filename =  _dir + "/" + hash_list
    dirname = os.path.dirname(filename)
    if not os.path.exists (dirname):
        os.makedirs(dirname)

    hash_list = []
    push_list = []
# load old hash list
    if  os.path.exists(filename):
        hash_file = open(filename, 'r')
        for line in hash_file:
            fhash, fmodified, fname = line.strip().split(" ", 2)
            hash_list.append([fhash.strip(), fmodified.strip(), fname.strip()])
        hash_file.close()

# find changes in repository
    list_files = _get_local_file_list(_dir)
    hash_list_files = [row[2] for row in hash_list]
    for file_path in list_files:
        file_path_r = file_path.replace(_dir, "./").replace("//", "/")
        file_hash = "0"
        file_modified = int(float(os.path.getmtime(file_path)))
        if cmp_hash:
            file_hash = _get_hash(file_path)
        print "\r"+file_path_r,
        try:
            index = hash_list_files.index(file_path_r)
            if (cmp_hash and hash_list[index][0] == file_hash)\
               or ( (not cmp_hash) and int(hash_list[index][1]) >= int(file_modified)):
                if os.path.exists(file_path.replace(_dir, _dest)):
                    file_hash = hash_list[index][0]
                    push_list.append([file_hash, file_modified, file_path_r, ""])
                    continue
                else:
                    file_hash = _get_hash(file_path)
                    push_list.append([file_hash, file_modified, file_path_r, file_path])
                    print "\r  [missing]",
            else:
                file_hash = _get_hash(file_path)
                push_list.append([file_hash, file_modified, file_path_r, file_path])
                hash_list.pop(index)
                hash_list_files.pop(index)
                print "\r  [modified]",
        except ValueError:
            file_hash = _get_hash(file_path)
            push_list.append([file_hash, file_modified, file_path_r, file_path])
            print "\r  [new file]",
        print file_path_r

# find unuseful files at remote
    orphan = []
    list_files = _get_remote_file_list(_dest)
    for file_path in list_files:
        file_name = file_path.replace(_dest, _dir)
        if not os.path.isfile(file_name):
            orphan.append(file_path)
            print "\r  [deleted]  " + file_path.replace(_dest, ".")

    print "\r[OK]"
    return push_list, orphan

def _send_remote(_dir, _dest, push_list, key, hash_name="default"):
    """Encript and copy it to remote dir
    _dir       local backup
    _dest      remote encrypted dir
     push_list list of files to be sent
    key        encryption key 32 characters
    hash_name  hash-list name for multiple remotes
    """
    print "Pushing to", _dest,
# create new hash-file, backup old one
    hash_list = "encrypt/"+hash_name+".sha1"
    filename = _dir + "/" + hash_list
    if os.path.exists(filename):
        copyfile(filename, filename+".old")
    hash_file = open(filename, 'w')
# prepare list of files to push
    push_files = []
    for file_hash, file_modified, file_path_r, file_path in push_list:
        hash_file.write(file_hash + " " + \
                str(file_modified) + " " + \
                file_path_r + "\n")
        if not file_path == "":
            push_files.append(file_path)
    hash_file.close()

    total = len(push_files)
    print "\t",total,"files to push"
# encrypt and push
    for in_filename in push_files:
        print "\r(" + str(push_files.index(in_filename) + 1) + \
              "/" + str(total) + ")", in_filename,
        out_filename = in_filename.replace(_dir, _dest)
        # backup remote file instead of delete
        if os.path.exists(out_filename):
            newfile = out_filename.replace(_dest, _dest+"deleted/")
            newfile += "." + datetime.datetime.now().strftime('%Y%m%d-%H%M%S')
            move(out_filename, newfile)
        in_file  = open(in_filename, 'rb')
        out_file = open(out_filename, 'wb')
        encrypt(in_file, out_file, KEY)
        in_file.close()
        out_file.close()
    print "\r[OK]"
    return 0

def _clean_remote(_dest, orphan):
    """Delete useless files at remote (not in local copy)
    _dest   remote encrypted dir
    orphan  list of files living only at remote
    """
    print "Cleaning  ", _dest,
    total = len(orphan)
    print "\t",total,"files to delete"
    for fname in orphan:
        print "\r(" + str(orphan.index(fname) + 1) + \
                "/" + str(total) + ")", fname,
        newfile = fname.replace(_dest, _dest+"deleted/")
        newfile += "." + datetime.datetime.now().strftime('%Y%m%d-%H%M%S')
        move(fname, newfile)
    print "\r[OK]"
    return 0

def _push_remote(_dir, _dest, key, cmp_hash=False):
    """Push and encrypt backup
    _dir       local backup
    _dest      remote encrypted dir
    puch_list  list of files to be pushed 
    key        encryption key 32 characters
    hash_name  hash-list name for multiple remotes
    cmp_hash   compare local files by hash intead of modified
    """
    index = 0
    while True:
        index += 1
        _break = True
        if _sync_dirs(_dir, _dest):
            print "\n[failed] Sync dirs failed."
            exit(1)

        push_list,orphan = \
        _get_diff(_dir, _dest, cmp_hash)
        if filter(lambda a: a != '', [row[3] for row in push_list]):
            _break = False

        if _send_remote(_dir, _dest, push_list , key):
            print "\n[failed] Send to remote failed."
            exit(1)

        if _clean_remote(_dest, orphan):
            print "\n[failed] Clean remote failed."
            exit(1)

        if _check_backup(_dir, _dest):
            _break = False

        if _break:
            return 0
# if is sth. wrong
        if index > 16:
            return 1

def _check_backup(_dir,_dest):
    """Check if all local files are on remote
    _dir       local backup
    _dest      remote encrypted backup
    """
    print "Checking backup"
    orphan = []
    list_files = _get_local_file_list(_dir)
    total = len(list_files)
    for file_name in list_files:
        print "\r(" + str(list_files.index(file_name) + 1) + "/" + \
                str(total) + ") " + \
                file_name.replace(_dest, "./"),
        dest_file_name = file_name.replace(_dir, _dest)
        if not os.path.isfile(dest_file_name):
            orphan.append(file_name)
            print "\r  [not send]", file_name.replace(_dir, ".")
    print "\r[OK]"
    if len(orphan) == 0:
        return 0
    return 1

def _full_check_backup(_dir, _dest, key):
    """Decrypt remote and compare with local
    _dir       local backup
    _dest      remote encrypted dir
    key        encryption key 32 characters
    """
    print "Checking  backup deeply "+_dest
    errors = []
    temp_file = _dir + "/encrypt/tmp"
    list_files = _get_remote_file_list(_dest)
    total = len(list_files)
    for file_name in list_files:
        print "\r(" + str(list_files.index(file_name) + 1) + "/" + \
                str(total) + ") " + \
                file_name.replace(_dest, "./"),
        in_file  = open(file_name , 'rb')
        out_file = open(temp_file, 'wb')
        decrypt(in_file, out_file, KEY)
        in_file.close()
        out_file.close()
        loc_file_name = file_name.replace(_dest,_dir)
        match = cmp(temp_file, loc_file_name)
        os.remove(temp_file)
        if not match:
            errors.append(loc_file_name)
            print "\r  [not match]",loc_file_name.replace(_dir, "./")
    if len(errors) > 0:
        print "\r[failed]"
    else:
        print "\r[OK]"
    return errors

###########################################################
# Repair remote backup
# _dir       local backup
# _dest      remote encrypted dir
# key        encryption key 32 characters
#
def _full_repair_backup(_dir, _dest, key , errors):
    total = len(errors)
    print "Full repair backup "+_dest,
    print "\t",total,"files to repair"
    for f in errors:
        print "\r(" + str(errors.index(f) + 1) + "/" + \
                str(total) + ") " + \
                f.replace(_dest, "./"),
        fname   = f.replace(_dir, _dest)
        newfile = fname.replace(_dest, _dest+"deleted/")
        newfile += "." + datetime.datetime.now().strftime('%Y%m%d-%H%M%S')
        move(fname, newfile)
    print "\r[OK]"
    if not total == 0:
        if _push_remote(_dir, _dest, key):
            print "\n[failed] Push failed."
            return 1
    return 0

def _pull_remote(_dir, _dest, key):
    """Decrypt remote and save it in local
    _dir       local dir for decryption
    _dest      remote encrypted dir
    key        encryption key 32 characters
    """
    print "Recovering from "+_dest
    list_files = _get_remote_file_list(_dest)
    total = len(list_files)
    for file_name in list_files:
        print "\r(" + str(list_files.index(file_name) + 1) + "/" + \
                str(total) + ") " + \
                file_name.replace(_dest, "./"),
        in_filename = file_name
        out_filename = in_filename.replace(_dest, _dir)
        in_file  = open(in_filename , 'rb')
        out_file = open(out_filename, 'wb')
        decrypt(in_file, out_file, KEY)
        in_file.close()
        out_file.close()
    print "\r[OK]"
    return 0

def _get_file_list(nullextra):
    """Returns list of files expanded from extra args
    """
    global extra
    cwd = os.getcwd()
    file_list = []
    _extra = []
    if not extra:
        _extra.append(nullextra)
    else:
        _extra = extra
 
    for fextra in _extra:
        if not os.path.exists(fextra):
            if not os.path.exists(cwd + "/" + fextra):
                print "[failed] File not found:",fextra
                exit(1)
            else:
                fextra = cwd + "/" + fextra
        if os.path.isdir(fextra):
            for path, dirs, files in os.walk(fextra):
                for f in files:
                    file_list.append(path + "/" + f)
        else:
            file_list.append(fextra)
    return file_list

def _get_remote_file_list(_dest):
    """Returns list of destination files from extra args
    """
    file_list = _get_file_list(_dest)
    file_list = filter(
            lambda a: a.find((_dest + "deleted").replace("//", "/")) == -1, 
            _get_file_list(nullextra=_dest))
    return file_list

def _get_local_file_list(_dir):
    """Returns list of local files from extra args
    """
    file_list = _get_file_list(_dir)
    file_list = filter(
            lambda a: a.find((_dir + "encrypt").replace("//", "/")) == -1, 
            _get_file_list(nullextra=_dir))
    return file_list

def _check_encryption_key():
    """Check if encryption key is set
    if not load from encript/.key
    if is not exist generate it
    """
    try:
        global KEY
        KEY 
    except NameError:
        keyfilename = BUP_DIR + "encrypt/.key"
        if not os.path.exists(keyfilename):
            dirname  = os.path.dirname(keyfilename)
            if not os.path.exists(dirname):
                os.makedirs(dirname) 
            print "Generating key in "+keyfilename
            cmd = "dd if=/dev/urandom of=" + keyfilename + " bs=1 count=32"
            print "Key gen command:", cmd
            os.system(cmd + ">/dev/null 2>&1")
        keyfile = open(keyfilename, "r")
        KEY = keyfile.read(32)
        keyfile.close()
        print "Using key-file    \t", keyfilename

def _check_encrypted_dir():
    """Check if encrypted dir is set
    If not set it from encrypt/.encryptdir .
    Test if the dir exists.
    """
    try:
        global ENCRYPT_DIR
        ENCRYPT_DIR
    except NameError:
        encfilename = BUP_DIR + "encrypt/.encryptdir"
        if not os.path.exists(encfilename):
            dirname  = os.path.dirname(encfilename)
            if not os.path.exists(dirname):
                os.makedirs(dirname)
            print "Missing file ./encrypt/.encryptdir or -e parameter."
            exit(1)
        encfile = open(encfilename, "r")
        ENCRYPT_DIR = encfile.readline().strip()
        encfile.close()
    ENCRYPT_DIR = (ENCRYPT_DIR + "/").replace("//", "/");
    if not os.path.exists(ENCRYPT_DIR):
        print "Encrypt path does not exist:",ENCRYPT_DIR
        exit(1)
    print "Using ecrypted dir\t", ENCRYPT_DIR

def _check_decrypted_dir():
    """Check if decryption dir is set.
    Test if the dir exists.
    """
    try:
        global DECRYPT_DIR
        DECRYPT_DIR
    except NameError:
        print "Missing -d parameter."
        exit(1)

    DECRYPT_DIR = (DECRYPT_DIR+"/").replace("//","/");
    if not os.path.exists(DECRYPT_DIR):
        print "Decrypt path does not exist:",DECRYPT_DIR
        exit(1)
    print "Using decription dir\t", DECRYPT_DIR

###########################################################
# help functions for necryption 
# http://stackoverflow.com/questions/16761458/how-to-aes-encrypt-decrypt-files-using-python-pycrypto-in-an-openssl-compatible
###########################################################
def derive_key_and_iv(password, salt, key_length, iv_length):
    d = d_i = ''
    while len(d) < key_length + iv_length:
        d_i = md5(d_i + password + salt).digest()
        d += d_i
    return d[:key_length], d[key_length:key_length+iv_length]

def encrypt(in_file, out_file, password, key_length=32):
    bs = AES.block_size
    salt = Random.new().read(bs - len('Salted__'))
    key, iv = derive_key_and_iv(password, salt, key_length, bs)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    out_file.write('Salted__' + salt)
    finished = False
    while not finished:
        chunk = in_file.read(1024 * bs)
        if len(chunk) == 0 or len(chunk) % bs != 0:
            padding_length = (bs - len(chunk) % bs) or bs
            chunk += padding_length * chr(padding_length)
            finished = True
        out_file.write(cipher.encrypt(chunk))

def decrypt(in_file, out_file, password, key_length=32):
    bs = AES.block_size
    salt = in_file.read(bs)[len('Salted__'):]
    key, iv = derive_key_and_iv(password, salt, key_length, bs)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    next_chunk = ''
    finished = False
    while not finished:
        chunk, next_chunk = next_chunk, cipher.decrypt(in_file.read(1024 * bs))
        if len(next_chunk) == 0:
            padding_length = ord(chunk[-1])
            chunk = chunk[:-padding_length]
            finished = True
        out_file.write(chunk)

def _get_hash(filepath):
    sha1 = hashlib.sha1()
    f = open(filepath, 'rb')
    try:
        sha1.update(f.read())
    finally:
        f.close()
    return sha1.hexdigest()


###########################################################
# main code
###########################################################

o = options.Options(optspec)
(opt, flags, extra) = o.parse(sys.argv[1:])

BUP_DIR = os.environ['BUP_DIR']
BUP_DIR = (BUP_DIR+"/").replace("//","/");

git.check_repo_or_die()

# load options
for (option, parameter) in flags:
    if   option == "-e" or option == "--encrypt":
        ENCRYPT_DIR = parameter
    elif option == "-k" or option == "--key":
        KEY = parameter
    elif option == "-d" or option == "--decrypt":
        DECRYPT_DIR = parameter

# commands
# push
if opt.push:
    _check_encryption_key()
    _check_encrypted_dir()

    if _push_remote(BUP_DIR, ENCRYPT_DIR, KEY, opt.full):
        print "\n[failed] Push failed."
        exit(1)

    print "\nPush successfull."

# check
elif opt.check and not opt.full:
    _check_encrypted_dir()

    push_list,orphan = _get_diff(BUP_DIR, ENCRYPT_DIR)
    check_backup = _check_backup(BUP_DIR, ENCRYPT_DIR)
    push_list = filter(lambda a: a != '', [row[3] for row in push_list])
    if len(push_list) > 0 or len(orphan) > 0 or check_backup:
        print "\n[failed] Remote is not synchonized."
        exit(1)

    print "\nRemote is synchonized."

# full check
elif opt.check and opt.full:
    _check_encryption_key()
    _check_encrypted_dir()

    if _sync_dirs(BUP_DIR, ENCRYPT_DIR):
        print "\n[failed] Sync dirs failed."
        exit(1)

    push_list,orphan = _get_diff(BUP_DIR, ENCRYPT_DIR)
    check_backup = _check_backup(BUP_DIR, ENCRYPT_DIR)
    push_list = filter(lambda a: a != '', [row[3] for row in push_list])
    if len(push_list) > 0 or len(orphan) > 0 or check_backup:
        print "\n[failed] Remote is not synchonized."
        exit(1)

    if _full_check_backup(BUP_DIR, ENCRYPT_DIR, KEY):
        print "\n[failed] Remote is not synchonized."
        exit(1)

    print "\nRemote is fully synchonized."

# pull
elif opt.decrypt:
    _check_encryption_key()
    _check_encrypted_dir()
    _check_decrypted_dir()

    if _sync_dirs(ENCRYPT_DIR, DECRYPT_DIR):
        print "\n[failed] Sync dirs failed."
        exit(1)

    if _pull_remote(DECRYPT_DIR, ENCRYPT_DIR, KEY):
        print "\n[failed] Pull failed."

    print "\nRepository decrypted."

# repair
elif opt.repair:
    _check_encryption_key()
    _check_encrypted_dir()

    if _push_remote(BUP_DIR, ENCRYPT_DIR, KEY, cmp_hash=True):
        print "\n[failed] Push failed."
        exit(1)

    errors = _full_check_backup(BUP_DIR, ENCRYPT_DIR, KEY)
    if _full_repair_backup(BUP_DIR, ENCRYPT_DIR, KEY, errors):
        print "\n[failed] Repair failed"

    print "\n Remote repository repaired."

# no command
else:
    o.fatal("use one of -p, -c, -d, --repair")
