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
                    push_list.append ( [file_hash, file_path_r, ""] )
                    continue
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
    orphan = []
    for path, dirs, files in os.walk( _dir ):
        if path == (_dir+"/hash").replace("//","/"):
            continue
        for f in files:
            filename = (path+"/"+f).replace ( _dir, _dest )
            if not os.path.isfile ( filename ):
                orphan.append ( path+"/"+f )
    if len ( orphan ) == 0:
        print "[OK]"
        return 0
    print "Not send yet:"
    for fname in orphan:
        print "  "+fname
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
                print "  [not match]",filename.replace ( _dir, "./" )
    if len ( errors ) > 0:
        print "\r[failed]"
    else:
        print "\r[OK]"
    return errors

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

###########################################################
# help functions
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
###########################################################

###########################################################
# main code
###########################################################

optspec = """
bup encrypt [-pcf] [-e encrypt-dir]
--
e,encrypt=      path to remote dir
d,decrypt=      path to local dir
k,key=          encryption key
p,push          push to remote directory
c,check         check remote backup
f,full          full check remote backup (takes long time)
"""
#optspec = """
#bup save [-tc] [-n name] <filenames...>
#--
#r,remote=  hostname:/path/to/repo of remote repository
#t,tree     output a tree id
#c,commit   output a commit id
#n,name=    name of backup set to update (if any)
#d,date=    date for the commit (seconds since the epoch)
#v,verbose  increase log output (can be used more than once)
#q,quiet    don't show progress meter
#smaller=   only back up files smaller than n bytes
#bwlimit=   maximum bytes/sec to transmit to server
#f,indexfile=  the name of the index file (normally BUP_DIR/bupindex)
#strip      strips the path to every filename given
#strip-path= path-prefix to be stripped when saving
#graft=     a graft point *old_path*=*new_path* (can be used more than once)
##,compress=  set compression level to # (0-9, 9 is highest) [1]
#"""

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


try:
    ENCRYPT_DIR
except NameError:
    print "Missing encrypt dir path, run witn -e"
    exit ( 1 )

BACKUP_DIR  = (BACKUP_DIR+"/").replace("//","/");
ENCRYPT_DIR = (ENCRYPT_DIR+"/").replace("//","/");
DECRYPT_DIR = (DECRYPT_DIR+"/").replace("//","/");

for (option, parameter) in flags:
    if option == "-p" or option == "--push":
        _check_encryption_key ()
        while True:
            _break = True
            if _sync_dirs    ( BACKUP_DIR, ENCRYPT_DIR ):
                print "\n[failed] Push failed."
                exit ( 1 )

            push_list,orphan = \
            _get_diff     ( BACKUP_DIR, ENCRYPT_DIR )
            if len ( filter(lambda a: a != '', [row[2] for row in push_list] ) ) > 0:
                _break = False

            if _send_remote  ( BACKUP_DIR, ENCRYPT_DIR, push_list , KEY ):
                print "\n[failed] Push failed."
                exit ( 1 )

            if _clean_remote ( ENCRYPT_DIR, orphan ):
                print "\n[failed] Push failed."
                exit ( 1 )

            if _check_backup ( BACKUP_DIR, ENCRYPT_DIR ):
                _break = False
            if _break:
                break
        print "\nPush successfull."
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

    elif option == "-f" or option == "--full":
        _check_encryption_key ()
        if _sync_dirs    ( BACKUP_DIR, ENCRYPT_DIR ):
            print "\n[failed] Push failed."
            exit ( 1 )
        push_list,orphan = \
        _get_diff          ( BACKUP_DIR, ENCRYPT_DIR )

        check_backup = \
        _check_backup      ( BACKUP_DIR, ENCRYPT_DIR )

        push_list = filter(lambda a: a != '', [row[2] for row in push_list] )
        if len ( push_list ) > 0 or len ( orphan ) > 0 or check_backup:
            print "\n[failed] Remote is not synchonized."
            exit ( 1 )
        full_check_backup = \
        _full_check_backup ( BACKUP_DIR, ENCRYPT_DIR, KEY )
        if len ( full_check_backup ) > 0:
            print "\n[failed] Remote is not synchonized."
            exit ( 1 )
        print "\nRemote is fully synchonized."
    elif option == "-d" or option == "--decrypt":
        _check_encryption_key ()
        if _sync_dirs ( ENCRYPT_DIR, DECRYPT_DIR ):
            print "\n[failed] Push failed."
            exit ( 1 )
        _pull_remote ( DECRYPT_DIR, ENCRYPT_DIR, KEY )

exit(0);




################################################################
### Trash
################################################################
optspec = """
bup save [-tc] [-n name] <filenames...>
--
r,remote=  hostname:/path/to/repo of remote repository
t,tree     output a tree id
c,commit   output a commit id
n,name=    name of backup set to update (if any)
d,date=    date for the commit (seconds since the epoch)
v,verbose  increase log output (can be used more than once)
q,quiet    don't show progress meter
smaller=   only back up files smaller than n bytes
bwlimit=   maximum bytes/sec to transmit to server
f,indexfile=  the name of the index file (normally BUP_DIR/bupindex)
strip      strips the path to every filename given
strip-path= path-prefix to be stripped when saving
graft=     a graft point *old_path*=*new_path* (can be used more than once)
#,compress=  set compression level to # (0-9, 9 is highest) [1]
"""
o = options.Options(optspec)
(opt, flags, extra) = o.parse(sys.argv[1:])

git.check_repo_or_die()
if not (opt.tree or opt.commit or opt.name):
    o.fatal("use one or more of -t, -c, -n")
if not extra:
    o.fatal("no filenames given")

opt.progress = (istty2 and not opt.quiet)
opt.smaller = parse_num(opt.smaller or 0)
if opt.bwlimit:
    client.bwlimit = parse_num(opt.bwlimit)

if opt.date:
    date = parse_date_or_fatal(opt.date, o.fatal)
else:
    date = time.time()

if opt.strip and opt.strip_path:
    o.fatal("--strip is incompatible with --strip-path")

graft_points = []
if opt.graft:
    if opt.strip:
        o.fatal("--strip is incompatible with --graft")

    if opt.strip_path:
        o.fatal("--strip-path is incompatible with --graft")

    for (option, parameter) in flags:
        if option == "--graft":
            splitted_parameter = parameter.split('=')
            if len(splitted_parameter) != 2:
                o.fatal("a graft point must be of the form old_path=new_path")
            old_path, new_path = splitted_parameter
            if not (old_path and new_path):
                o.fatal("a graft point cannot be empty")
            graft_points.append((realpath(old_path), realpath(new_path)))

is_reverse = os.environ.get('BUP_SERVER_REVERSE')
if is_reverse and opt.remote:
    o.fatal("don't use -r in reverse mode; it's automatic")

if opt.name and opt.name.startswith('.'):
    o.fatal("'%s' is not a valid branch name" % opt.name)
refname = opt.name and 'refs/heads/%s' % opt.name or None
if opt.remote or is_reverse:
    try:
        cli = client.Client(opt.remote)
    except client.ClientError, e:
        log('error: %s' % e)
        sys.exit(1)
    oldref = refname and cli.read_ref(refname) or None
    w = cli.new_packwriter(compression_level=opt.compress)
else:
    cli = None
    oldref = refname and git.read_ref(refname) or None
    w = git.PackWriter(compression_level=opt.compress)

handle_ctrl_c()


def eatslash(dir):
    if dir.endswith('/'):
        return dir[:-1]
    else:
        return dir


# Metadata is stored in a file named .bupm in each directory.  The
# first metadata entry will be the metadata for the current directory.
# The remaining entries will be for each of the other directory
# elements, in the order they're listed in the index.
#
# Since the git tree elements are sorted according to
# git.shalist_item_sort_key, the metalist items are accumulated as
# (sort_key, metadata) tuples, and then sorted when the .bupm file is
# created.  The sort_key must be computed using the element's real
# name and mode rather than the git mode and (possibly mangled) name.

# Maintain a stack of information representing the current location in
# the archive being constructed.  The current path is recorded in
# parts, which will be something like ['', 'home', 'someuser'], and
# the accumulated content and metadata for of the dirs in parts is
# stored in parallel stacks in shalists and metalists.

parts = [] # Current archive position (stack of dir names).
shalists = [] # Hashes for each dir in paths.
metalists = [] # Metadata for each dir in paths.


def _push(part, metadata):
    # Enter a new archive directory -- make it the current directory.
    parts.append(part)
    shalists.append([])
    metalists.append([('', metadata)]) # This dir's metadata (no name).


def _pop(force_tree, dir_metadata=None):
    # Leave the current archive directory and add its tree to its parent.
    assert(len(parts) >= 1)
    part = parts.pop()
    shalist = shalists.pop()
    metalist = metalists.pop()
    if metalist and not force_tree:
        if dir_metadata: # Override the original metadata pushed for this dir.
            metalist = [('', dir_metadata)] + metalist[1:]
        sorted_metalist = sorted(metalist, key = lambda x : x[0])
        metadata = ''.join([m[1].encode() for m in sorted_metalist])
        metadata_f = StringIO(metadata)
        mode, id = hashsplit.split_to_blob_or_tree(w.new_blob, w.new_tree,
                                                   [metadata_f],
                                                   keep_boundaries=False)
        shalist.append((mode, '.bupm', id))
    # FIXME: only test if collision is possible (i.e. given --strip, etc.)?
    if force_tree:
        tree = force_tree
    else:
        names_seen = set()
        clean_list = []
        for x in shalist:
            name = x[1]
            if name in names_seen:
                parent_path = '/'.join(parts) + '/'
                add_error('error: ignoring duplicate path %r in %r'
                          % (name, parent_path))
            else:
                names_seen.add(name)
                clean_list.append(x)
        tree = w.new_tree(clean_list)
    if shalists:
        shalists[-1].append((GIT_MODE_TREE,
                             git.mangle_name(part,
                                             GIT_MODE_TREE, GIT_MODE_TREE),
                             tree))
    return tree


lastremain = None
def progress_report(n):
    global count, subcount, lastremain
    subcount += n
    cc = count + subcount
    pct = total and (cc*100.0/total) or 0
    now = time.time()
    elapsed = now - tstart
    kps = elapsed and int(cc/1024./elapsed)
    kps_frac = 10 ** int(math.log(kps+1, 10) - 1)
    kps = int(kps/kps_frac)*kps_frac
    if cc:
        remain = elapsed*1.0/cc * (total-cc)
    else:
        remain = 0.0
    if (lastremain and (remain > lastremain)
          and ((remain - lastremain)/lastremain < 0.05)):
        remain = lastremain
    else:
        lastremain = remain
    hours = int(remain/60/60)
    mins = int(remain/60 - hours*60)
    secs = int(remain - hours*60*60 - mins*60)
    if elapsed < 30:
        remainstr = ''
        kpsstr = ''
    else:
        kpsstr = '%dk/s' % kps
        if hours:
            remainstr = '%dh%dm' % (hours, mins)
        elif mins:
            remainstr = '%dm%d' % (mins, secs)
        else:
            remainstr = '%ds' % secs
    qprogress('Saving: %.2f%% (%d/%dk, %d/%d files) %s %s\r'
              % (pct, cc/1024, total/1024, fcount, ftotal,
                 remainstr, kpsstr))


indexfile = opt.indexfile or git.repo('bupindex')
r = index.Reader(indexfile)
try:
    msr = index.MetaStoreReader(indexfile + '.meta')
except IOError, ex:
    if ex.errno != EACCES:
        raise
    log('error: cannot access %r; have you run bup index?' % indexfile)
    sys.exit(1)
hlink_db = hlinkdb.HLinkDB(indexfile + '.hlink')

def already_saved(ent):
    return ent.is_valid() and w.exists(ent.sha) and ent.sha

def wantrecurse_pre(ent):
    return not already_saved(ent)

def wantrecurse_during(ent):
    return not already_saved(ent) or ent.sha_missing()

def find_hardlink_target(hlink_db, ent):
    if hlink_db and not stat.S_ISDIR(ent.mode) and ent.nlink > 1:
        link_paths = hlink_db.node_paths(ent.dev, ent.ino)
        if link_paths:
            return link_paths[0]

total = ftotal = 0
if opt.progress:
    for (transname,ent) in r.filter(extra, wantrecurse=wantrecurse_pre):
        if not (ftotal % 10024):
            qprogress('Reading index: %d\r' % ftotal)
        exists = ent.exists()
        hashvalid = already_saved(ent)
        ent.set_sha_missing(not hashvalid)
        if not opt.smaller or ent.size < opt.smaller:
            if exists and not hashvalid:
                total += ent.size
        ftotal += 1
    progress('Reading index: %d, done.\n' % ftotal)
    hashsplit.progress_callback = progress_report

# Root collisions occur when strip or graft options map more than one
# path to the same directory (paths which originally had separate
# parents).  When that situation is detected, use empty metadata for
# the parent.  Otherwise, use the metadata for the common parent.
# Collision example: "bup save ... --strip /foo /foo/bar /bar".

# FIXME: Add collision tests, or handle collisions some other way.

# FIXME: Detect/handle strip/graft name collisions (other than root),
# i.e. if '/foo/bar' and '/bar' both map to '/'.

first_root = None
root_collision = None
tstart = time.time()
count = subcount = fcount = 0
lastskip_name = None
lastdir = ''
for (transname,ent) in r.filter(extra, wantrecurse=wantrecurse_during):
    (dir, file) = os.path.split(ent.name)
    exists = (ent.flags & index.IX_EXISTS)
    hashvalid = already_saved(ent)
    wasmissing = ent.sha_missing()
    oldsize = ent.size
    if opt.verbose:
        if not exists:
            status = 'D'
        elif not hashvalid:
            if ent.sha == index.EMPTY_SHA:
                status = 'A'
            else:
                status = 'M'
        else:
            status = ' '
        if opt.verbose >= 2:
            log('%s %-70s\n' % (status, ent.name))
        elif not stat.S_ISDIR(ent.mode) and lastdir != dir:
            if not lastdir.startswith(dir):
                log('%s %-70s\n' % (status, os.path.join(dir, '')))
            lastdir = dir

    if opt.progress:
        progress_report(0)
    fcount += 1
    
    if not exists:
        continue
    if opt.smaller and ent.size >= opt.smaller:
        if exists and not hashvalid:
            if opt.verbose:
                log('skipping large file "%s"\n' % ent.name)
            lastskip_name = ent.name
        continue

    assert(dir.startswith('/'))
    if opt.strip:
        dirp = stripped_path_components(dir, extra)
    elif opt.strip_path:
        dirp = stripped_path_components(dir, [opt.strip_path])
    elif graft_points:
        dirp = grafted_path_components(graft_points, dir)
    else:
        dirp = path_components(dir)

    # At this point, dirp contains a representation of the archive
    # path that looks like [(archive_dir_name, real_fs_path), ...].
    # So given "bup save ... --strip /foo/bar /foo/bar/baz", dirp
    # might look like this at some point:
    #   [('', '/foo/bar'), ('baz', '/foo/bar/baz'), ...].

    # This dual representation supports stripping/grafting, where the
    # archive path may not have a direct correspondence with the
    # filesystem.  The root directory is represented by an initial
    # component named '', and any component that doesn't have a
    # corresponding filesystem directory (due to grafting, for
    # example) will have a real_fs_path of None, i.e. [('', None),
    # ...].

    if first_root == None:
        first_root = dirp[0]
    elif first_root != dirp[0]:
        root_collision = True

    # If switching to a new sub-tree, finish the current sub-tree.
    while parts > [x[0] for x in dirp]:
        _pop(force_tree = None)

    # If switching to a new sub-tree, start a new sub-tree.
    for path_component in dirp[len(parts):]:
        dir_name, fs_path = path_component
        # Not indexed, so just grab the FS metadata or use empty metadata.
        try:
           meta = metadata.from_path(fs_path) if fs_path else metadata.Metadata()
        except (OSError, IOError), e:
            add_error(e)
            lastskip_name = dir_name
            meta = metadata.Metadata()
        _push(dir_name, meta)

    if not file:
        if len(parts) == 1:
            continue # We're at the top level -- keep the current root dir
        # Since there's no filename, this is a subdir -- finish it.
        oldtree = already_saved(ent) # may be None
        newtree = _pop(force_tree = oldtree)
        if not oldtree:
            if lastskip_name and lastskip_name.startswith(ent.name):
                ent.invalidate()
            else:
                ent.validate(GIT_MODE_TREE, newtree)
            ent.repack()
        if exists and wasmissing:
            count += oldsize
        continue

    # it's not a directory
    id = None
    if hashvalid:
        id = ent.sha
        git_name = git.mangle_name(file, ent.mode, ent.gitmode)
        git_info = (ent.gitmode, git_name, id)
        shalists[-1].append(git_info)
        sort_key = git.shalist_item_sort_key((ent.mode, file, id))
        meta = msr.metadata_at(ent.meta_ofs)
        meta.hardlink_target = find_hardlink_target(hlink_db, ent)
        # Restore the times that were cleared to 0 in the metastore.
        (meta.atime, meta.mtime, meta.ctime) = (ent.atime, ent.mtime, ent.ctime)
        metalists[-1].append((sort_key, meta))
    else:
        if stat.S_ISREG(ent.mode):
            try:
                f = hashsplit.open_noatime(ent.name)
            except (IOError, OSError), e:
                add_error(e)
                lastskip_name = ent.name
            else:
                try:
                    (mode, id) = hashsplit.split_to_blob_or_tree(
                                            w.new_blob, w.new_tree, [f],
                                            keep_boundaries=False)
                except (IOError, OSError), e:
                    add_error('%s: %s' % (ent.name, e))
                    lastskip_name = ent.name
        else:
            if stat.S_ISDIR(ent.mode):
                assert(0)  # handled above
            elif stat.S_ISLNK(ent.mode):
                try:
                    rl = os.readlink(ent.name)
                except (OSError, IOError), e:
                    add_error(e)
                    lastskip_name = ent.name
                else:
                    (mode, id) = (GIT_MODE_SYMLINK, w.new_blob(rl))
            else:
                # Everything else should be fully described by its
                # metadata, so just record an empty blob, so the paths
                # in the tree and .bupm will match up.
                (mode, id) = (GIT_MODE_FILE, w.new_blob(""))

        if id:
            ent.validate(mode, id)
            ent.repack()
            git_name = git.mangle_name(file, ent.mode, ent.gitmode)
            git_info = (mode, git_name, id)
            shalists[-1].append(git_info)
            sort_key = git.shalist_item_sort_key((ent.mode, file, id))
            hlink = find_hardlink_target(hlink_db, ent)
            try:
                meta = metadata.from_path(ent.name, hardlink_target=hlink)
            except (OSError, IOError), e:
                add_error(e)
                lastskip_name = ent.name
            else:
                metalists[-1].append((sort_key, meta))

    if exists and wasmissing:
        count += oldsize
        subcount = 0


if opt.progress:
    pct = total and count*100.0/total or 100
    progress('Saving: %.2f%% (%d/%dk, %d/%d files), done.    \n'
             % (pct, count/1024, total/1024, fcount, ftotal))

while len(parts) > 1: # _pop() all the parts above the root
    _pop(force_tree = None)
assert(len(shalists) == 1)
assert(len(metalists) == 1)

# Finish the root directory.
tree = _pop(force_tree = None,
            # When there's a collision, use empty metadata for the root.
            dir_metadata = metadata.Metadata() if root_collision else None)

if opt.tree:
    print tree.encode('hex')
if opt.commit or opt.name:
    msg = 'bup save\n\nGenerated by command:\n%r\n' % sys.argv
    commit = w.new_commit(oldref, tree, date, msg)
    if opt.commit:
        print commit.encode('hex')

msr.close()
w.close()  # must close before we can update the ref
        
if opt.name:
    if cli:
        cli.update_ref(refname, commit, oldref)
    else:
        git.update_ref(refname, commit, oldref)

if cli:
    cli.close()

if saved_errors:
    log('WARNING: %d errors encountered while saving.\n' % len(saved_errors))
    sys.exit(1)
