.. testsetup:: *

   from pwn import *
   old = context.defaults.copy()

.. testcleanup:: *

    context.defaults.copy = old

Command Line Tools
========================

.. pwntools comes with a handful of useful command-line utilities which serve as wrappers for some of the internal functionality.

pwntoolsには、いくつかの内部機能のラッパーとして機能する、便利なコマンドラインユーティリティが付属しています。

.. If these tools do not appear to be installed, make sure that you have added ``~/.local/bin`` to your ``$PATH`` environment variable.

これらのツールがインストールされていないようであれば、環境変数 ``$PATH`` に ``~/.local/bin`` が追加されているかどうかを確認してください。

.. toctree::

.. autoprogram:: pwnlib.commandline.main:parser
   :prog: pwn
