% bup-encrypt(1) Bup %BUP_VERSION%
% Lukáš Ledvina <lukasledvina@gmail.com>
% %BUP_DATE%

# NAME

bup-encrypt - encrypt a bup repository (file by file) with (openssl aes-256-cbc -salt)

# SYNOPSIS
bup encrypt <-p|-c|-d|--repair> [-f] [-k *key*] 
[-d *decrypt-dir*] [-e *encrypt-dir*] \<paths ...\>;

# DESCRIPTION

`bup encrypt` makes an encrypted copy of the repository in the another place
of the file system. Optionally the destination directory is mounted remotely
(i.e. googledrive, sshfs, nfs,...).

The key is stored in repository in *encrypt/.key*. If it is not set before 
running first command *bup encrypt* it is generated automatically from 
*/dev/urandom*.
Beware, without the key are encrypted backups completely inaccessible, please 
copy it to another location for disk failure case. You can change a key but 
than you must run *bup encrypt --repair* or delete remote backups and 
use *bup encrypt -p* (quicker).

Path to the encrypted directory is stored in *encrypt/.encryptdir*. It can also
be set by *-e* flag.

Subdirectory encrypt is not pushed to remote because of security reasons.

Files which might be modified or deleted in remote directory are moved 
to *deleted* subdirectory (in remote dir only), timestamp to their name 
is added.

By default are pushed, checked, decrypted or repaired all files in the 
repository.

# OPTIONS

-p, \--push
:   push and encrypt local changes into remote directory. If it is used
    without *-f* it uses modify timestamp in files, with *-f* it checks 
    all checksums of all files in repository (slower).

-c, \--check
:   check if all local files are pushed and if in the remote directory are not
    locally deleted files. Without *-f* it uses only modify timestamps.
    With *-f* if downloads all items from the remote repository, decrypt them
    and compare with the local files (very slow).

-d, \--decrypt=*path*
:   download the remote directory and decrypt it to the *path*.

\--repair
:   repair remote directory. It calls twice bup with *-cf* -- if dowloads
    twice whole repository.
    It encrypts all files from remote and compare them to local repository
    then it pushes corrupted files and check repository ones more.

-f, \--full
:   use checksums instead of modify timestamps. For more details 
    see *--push* and *--check*.

-e, \--encrypt=*path*
:   overwrites remote encrypted directory loaded from *encrypt/.encryptdir*.

-k, \--key=*32chars key*
:   overwrites encryption key loaded from *encrypt/.key*. 
    Length of the key must be 32 characters!

# EXAMPLES
                            1234567890123456789012345789012
    $ bup encrypt -p -f -k "the best key Im able to imagine" -e /mnt/google-drive/backups/
    ...
    Push successful.

    $ bup encrypt -c
    ...
    Remote is synchronized.

    $ bup encrypt -cf
    ...
    Remote is fully synchronized.

    $ bup encrypt --repair
    ...
    Remote repository repaired.

    $ bup encrypt -d /var/restore
    ...
    Repository decrypted.

# SEE ALSO

`bup-index`(1), `bup-save`(1), `bup-fsck`(1),

# BUP

Part of the `bup`(1) suite.
