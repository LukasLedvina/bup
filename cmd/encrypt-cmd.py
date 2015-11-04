#!/usr/bin/env python
import sys, stat, time, math

from bup import options
from bup.helpers import *

from shutil import copyfile
from filecmp import cmp

from hashlib import md5
from Crypto.Cipher import AES
from Crypto import Random

###########################################################
# important functions
###########################################################

###########################################################
# Synchronize directory structure
# _dir   local backup
# _dest  remote encrypted backup
#
def _sync_dirs ( _dir, _dest ):
    print "Synchonizing dirs\t",
    cmd='rsync -qa -f"+ */" -f"- *" '+_dir+" "+_dest
    ret = os.system(cmd)
    if ret == 0:
        print "[OK]"
    else:
        print "[failed] "+ret
        exit(1)
    return ret

###########################################################
# Compares hashes in local backup with local hash-list
# prepare list of files to push
# _dir       local backup
# _dest      remote encrypted backup
# hash_name  hash-list name for multiple remotes
#
def _get_diff ( _dir, _dest, hash_name="default" ):
    print "Calculate diff"
    hash_list="hash/"+hash_name+".sha1"
    filename =  _dir+"/"+hash_list
    dirname  = os.path.dirname ( filename )
    if not os.path.exists ( dirname ):
        os.makedirs ( dirname )

    hash_list = []
    push_list = []
# load old hash list
    if  os.path.exists ( filename ):
        hash_file = open ( filename, 'r' )
        for line in hash_file:
            fhash, fname = line.strip().split(" ", 1)
            hash_list.append( [fhash.strip(), fname.strip()] )
        hash_file.close()

# find changes in repository
    list_file = [row[1] for row in hash_list]
    for path, dirs, files in os.walk( _dir ):
        if path == (_dir+"/hash").replace("//","/"):
            continue
        for f in files:
            file_path   = ( path + "/" + f ).replace ( "//", "/" )
            file_hash   = _get_hash ( file_path )
            file_path_r = file_path.replace ( _dir, "./" ).replace ( "//", "/" )
            print "\r"+file_path_r,
            try:
                index = list_file.index ( file_path_r )
                if hash_list[index][0] == file_hash:
                    if os.path.exists ( file_path.replace ( _dir, _dest ) ):
                        push_list.append ( [file_hash, file_path_r, ""] )
                        continue
                    else:
                        push_list.append ( [file_hash, file_path_r, file_path] )
                        print "\r  [missing]",
                else:
                    print "\r  [modified]",
                    push_list.append ( [file_hash, file_path_r, file_path] )
                    hash_list.pop ( index )
                    list_file.pop ( index )
            except ValueError:
                print "\r  [new file]",
                push_list.append ( [file_hash, file_path_r, file_path] )
            print file_path_r
# find unuseful files at remote
    orphan = []
    for path, dirs, files in os.walk( _dest ):
        for f in files:
            filename = (path+"/"+f).replace ( _dest, _dir )
            if not os.path.isfile ( filename ):
                orphan.append ( path+"/"+f )
    for fname in orphan:
        print "\r  [deleted] "+fname

    print "\r[OK]"
    return push_list, orphan

###########################################################
# Encrypt and send files to remote
# _dir       local backup
# _dest      remote encrypted dir
# puch_list  list of files to be pushed 
# key        encryption key 32 characters
# hash_name  hash-list name for multiple remotes
#
def _send_remote ( _dir, _dest, push_list, key, hash_name="default" ):
    print "Pushing to", _dest,
# create new hash-file, backup old one
    hash_list = "hash/"+hash_name+".sha1"
    filename = _dir + "/" + hash_list
    if os.path.exists ( filename ):
        copyfile ( filename, filename+".old" )
    hash_file = open ( filename, 'w' )
# prepare list of files to push
    push_files = []
    for file_hash, file_path_r, file_path in push_list:
        hash_file.write ( file_hash + " " + file_path_r + "\n" )
        if not file_path == "":
            push_files.append ( file_path )
    hash_file.close ()

    total = len ( push_files )
    print "\t",total,"files to push"
# encrypt and push
    for in_filename in push_files:
        print "\r("+str(push_files.index ( in_filename )+1)+"/"+str(total)+")",in_filename,
        out_filename = in_filename.replace (_dir, _dest )
        in_file  = open(in_filename, 'rb') 
        out_file = open(out_filename, 'wb')
        encrypt ( in_file, out_file, KEY )
        in_file.close()
        out_file.close()
    print "\r[OK]"
    return 0

###########################################################
# Delete useless files at remote (not in local copy)
# _dest   remote encrypted dir
# orphan  list of files living only at remote
#
def _clean_remote (_dest, orphan ):
    print "Cleaning  ", _dest,
    total = len ( orphan )
    print "\t",total,"files to delete"
    for fname in orphan:
        print "\r(" + str ( orphan.index ( fname ) + 1 ) + \
                "/" + str ( total ) + ")", fname,
        os.remove ( fname )
    print "\r[OK]"
    return 0

###########################################################
# Check if all local files are on remote
# _dir       local backup
# _dest      remote encrypted backup
#
def _check_backup ( _dir, _dest ):
    print "Check backup"
    total = 0
    index = 0
    for path, dirs, files in os.walk( _dest ):
        total += len ( files )

    orphan = []
    for path, dirs, files in os.walk( _dir ):
        if path == (_dir+"/hash").replace("//","/"):
            continue
        for f in files:
            print "\r(" + str ( index + 1 ) + "/" + \
                    str ( total ) + ") " + \
                    ( path + "/" + f ).replace ( _dest, "./" ),
            index += 1
            filename = (path+"/"+f).replace ( _dir, _dest )
            if not os.path.isfile ( filename ):
                orphan.append ( path+"/"+f )
    if len ( orphan ) == 0:
        print "[OK]"
        return 0
    for fname in orphan:
        print "\r  [not send]", fname.replace ( _dir, "./" )
    print "[failed]"
    return 1

###########################################################
# Decrypt remote and compare with local
# _dir       local backup
# _dest      remote encrypted dir
# key        encryption key 32 characters
#
def _full_check_backup ( _dir, _dest, key ):
    print "Full check backup "+_dest
    total = 0
    index = 0
    for path, dirs, files in os.walk( _dest ):
        total += len ( files )

    errors = []
    temp_file = _dir + "/hash/tmp"
    for path, dirs, files in os.walk( _dest ):
        for f in files:
            print "\r(" + str ( index + 1 ) + "/" + \
                    str ( total ) + ") " + \
                    ( path + "/" + f ).replace ( _dest, "./" ),
            index += 1
            filename = path + "/" + f
            in_file  = open ( filename , 'rb')
            out_file = open ( temp_file, 'wb' )
            decrypt ( in_file, out_file, KEY )
            in_file.close()
            out_file.close()
            filename = filename.replace (_dest,_dir)
            match = cmp ( temp_file, filename )
            os.remove ( temp_file )
            if not match:
                errors.append ( filename )
                print "\r  [not match]",filename.replace ( _dir, "./" )
    if len ( errors ) > 0:
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
def _full_repair_backup ( _dir, _dest, key , errors):
    total = len ( errors )
    print "Full repair backup "+_dest,
    print "\t",total,"files to repair"
    for f in errors:
        print "\r(" + str ( errors.index ( f ) + 1 ) + "/" + \
                str ( total ) + ") " + \
                f.replace ( _dest, "./" ),
        os.remove ( f.replace ( _dir, _dest ) )
    print "\r[OK]"
    if not total == 0:
        _push_remote ( _dir, _dest, key )

###########################################################
# Decrypt remote and save it in local
# _dir       local dir for decryption
# _dest      remote encrypted dir
# key        encryption key 32 characters
#
def _pull_remote ( _dir, _dest, key ):
    print "Recovery from "+_dest
    total = 0
    index = 0
    for path, dirs, files in os.walk( _dest ):
        total += len ( files )

    for path, dirs, files in os.walk( _dest ):
        for f in files:
            print "\r(" + str ( index + 1 ) + "/" + \
                    str ( total ) + ") " + \
                    ( path + "/" + f ).replace ( _dest, "./" ),
            index += 1
            in_filename = path + "/" + f
            out_filename = in_filename.replace ( _dest, _dir )
            in_file  = open ( in_filename , 'rb')
            out_file = open ( out_filename, 'wb' )
            decrypt ( in_file, out_file, KEY )
            in_file.close()
            out_file.close()
    print "\r[OK]"

###########################################################
# Check if encryption key is set
#
def _check_encryption_key ():
    global KEY
    try:
        KEY
    except NameError:
        keyfilename = BACKUP_DIR + "/hash/.key"
        if not os.path.exists ( keyfilename ):
            dirname  = os.path.dirname ( keyfilename )
            if not os.path.exists ( dirname ):
                os.makedirs ( dirname ) 
            print "Generating key in "+keyfilename
            os.system ( "dd if=/dev/urandom of=" + keyfilename + " bs=1 count=32" )
        keyfile = open ( keyfilename, "r" )
        KEY = keyfile.read(32)
        keyfile.close()
        print "Using key-file", keyfilename

###########################################################
# Push and encrypt backup
# _dir       local backup
# _dest      remote encrypted dir
# puch_list  list of files to be pushed 
# key        encryption key 32 characters
# hash_name  hash-list name for multiple remotes
#
def _push_remote ( _dir, _dest, key ):
    index = 0
    while True:
        index += 1
        _break = True
        if _sync_dirs    ( _dir, _dest ):
            print "\n[failed] Push failed."
            exit ( 1 )

        push_list,orphan = \
        _get_diff     ( _dir, _dest )
        if len ( filter(lambda a: a != '', [row[2] for row in push_list] ) ) > 0:
            _break = False

        if _send_remote  ( _dir, _dest, push_list , key ):
            print "\n[failed] Push failed."
            exit ( 1 )

        if _clean_remote ( _dest, orphan ):
            print "\n[failed] Push failed."
            exit ( 1 )

        if _check_backup ( _dir, _dest ):
            _break = False

        if _break:
            return 0
        if index > 16:
            return 1

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

def _get_hash ( filepath ):
    sha1 = hashlib.sha1()
    f = open ( filepath, 'rb')
    try:
        sha1.update(f.read())
    finally:
        f.close()
    return sha1.hexdigest()


###########################################################
# main code
###########################################################
#
# full check -> repair push
# push separate files

optspec = """
bup encrypt [-pcf] [-k key] [-d decrypt-dir] [-e encrypt-dir]
--
e,encrypt=      path to remote dir
d,decrypt=      path to local dir
k,key=          encryption key
p,push          push to remote directory
c,check         check remote backup
f,full          full check remote backup (takes long time)
,repair-rem     full repair remote (takes long time)
"""

o = options.Options(optspec)
(opt, flags, extra) = o.parse(sys.argv[1:])

#print opt
#print flags
#print extra
#print "###############################"

BACKUP_DIR = os.environ['BUP_DIR']
DECRYPT_DIR=""

for (option, parameter) in flags:
    if option == "-e" or option == "--encrypt":
        ENCRYPT_DIR = parameter
    elif option == "-k" or option == "--key":
        KEY = parameter
    elif option == "-d" or option == "--decrypt":
        DECRYPT_DIR = parameter
        if DECRYPT_DIR == "":
            print "\n[failed] Missing decrypt directory."
            exit ( 1 )


try:
    ENCRYPT_DIR
except NameError:
    print "Missing encrypt dir path, run witn -e"
    exit ( 1 )

BACKUP_DIR  = (BACKUP_DIR+"/").replace("//","/");
ENCRYPT_DIR = (ENCRYPT_DIR+"/").replace("//","/");
DECRYPT_DIR = (DECRYPT_DIR+"/").replace("//","/");

for (option, parameter) in flags:
# push
    if option == "-p" or option == "--push":
        _check_encryption_key ()
        if _push_remote ( BACKUP_DIR, ENCRYPT_DIR, KEY ):
            print "\nPush successfull."
# check
    elif option == "-c" or option == "--check":
        push_list,orphan = \
        _get_diff     ( BACKUP_DIR, ENCRYPT_DIR )

        check_backup = \
        _check_backup ( BACKUP_DIR, ENCRYPT_DIR )

        push_list = filter(lambda a: a != '', [row[2] for row in push_list] )
        if len ( push_list ) > 0 or len ( orphan ) > 0 or check_backup:
            print "\n[failed] Remote is not synchonized."
            exit ( 1 )
        print "\nRemote is synchonized."
# full check
    elif option == "-f" or option == "--full":
        _check_encryption_key ()
        if _sync_dirs    ( BACKUP_DIR, ENCRYPT_DIR ):
            print "\n[failed] Sync dirs failed."
            exit ( 1 )
        push_list,orphan = \
        _get_diff          ( BACKUP_DIR, ENCRYPT_DIR )

        check_backup = \
        _check_backup      ( BACKUP_DIR, ENCRYPT_DIR )

        push_list = filter(lambda a: a != '', [row[2] for row in push_list] )
        if len ( push_list ) > 0 or len ( orphan ) > 0 or check_backup:
            print "\n[failed] Remote is not synchonized."
            exit ( 1 )

        if _full_check_backup ( BACKUP_DIR, ENCRYPT_DIR, KEY ):
            print "\n[failed] Remote is not synchonized."
            exit ( 1 )

        print "\nRemote is fully synchonized."
# pull
    elif option == "-d" or option == "--decrypt":
        _check_encryption_key ()
        if _sync_dirs ( ENCRYPT_DIR, DECRYPT_DIR ):
            print "\n[failed]Sync dirs failed."
            exit ( 1 )
        _pull_remote ( DECRYPT_DIR, ENCRYPT_DIR, KEY )
        print "\nRepository decrypted."
# repair
    elif option == "--repair-rem":
        _check_encryption_key ()
        _push_remote ( BACKUP_DIR, ENCRYPT_DIR, KEY )
        errors = _full_check_backup ( BACKUP_DIR, ENCRYPT_DIR, KEY )
        _full_repair_backup ( BACKUP_DIR, ENCRYPT_DIR, KEY, errors )


exit(0);

