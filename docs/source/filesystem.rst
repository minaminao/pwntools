.. testsetup:: *

    import time
    import six
    from pwnlib.context import context
    from pwnlib.tubes.ssh import ssh
    from pwnlib.filesystem import *

:mod:`pwnlib.filesystem` --- Manipulating Files Locally and Over SSH
====================================================================

.. Provides a Python2-compatible :py:mod:`pathlib` interface for paths
 on the local filesystem (`.Path`) as well as on remote filesystems,
 via SSH (`.SSHPath`).

Python2互換の :py:mod:`pathlib` インターフェースを提供します。ローカルファイルシステム上のパス (`.Path`) および SSH 経由のリモートファイルシステム上のパス (`.SSHPath`) のためのインターフェースです。

.. automodule:: pwnlib.filesystem
   :members: