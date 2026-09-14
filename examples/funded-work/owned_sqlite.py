"""Shared owner-local file boundary; the owning host remains trusted."""
import os
from pathlib import Path
import sqlite3
import stat

import artifacts as p


def open_owned(path, *, create=True):
    path=Path(os.path.abspath(path))
    parent=path.parent.stat(follow_symlinks=False)
    p.require(stat.S_ISDIR(parent.st_mode) and parent.st_uid==os.getuid()
              and stat.S_IMODE(parent.st_mode)==0o700, 'store parent must be owned mode 0700')
    created=False
    try:
        if create:
            try:
                fd=os.open(path,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
                created=True
            except FileExistsError:
                fd=os.open(path,os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK)
        else:
            fd=os.open(path,os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK)
    except OSError as error:
        raise p.ProtocolError('store missing or unsafe') from error
    try:
        info=os.fstat(fd)
        p.require(stat.S_ISREG(info.st_mode) and info.st_uid==os.getuid()
                  and stat.S_IMODE(info.st_mode)==0o600 and info.st_nlink==1, 'unsafe store ownership or mode')
    finally:
        os.close(fd)
    # The private directory and its same-UID administrator are trusted throughout.
    return sqlite3.connect(path,timeout=5),created


def sync_parent(path):
    directory=os.open(Path(path).parent,os.O_RDONLY|os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
