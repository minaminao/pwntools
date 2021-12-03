.. testsetup:: *

   from pwn import *

``from pwn import *``
========================

.. The most common way that you'll see pwntools used is

pwntoolsが使われる最も一般的な方法は以下の通りです。

    >>> from pwn import *

.. Which imports a bazillion things into the global namespace to make your life easier.

 This is a quick list of most of the objects and routines imported, in rough order of importance and frequency of use.

これは、あなたの生活を楽にするために、グローバルな名前空間にたくさんのものをインポートします。

これは、インポートされたオブジェクトとルーチンのほとんどを、重要度と使用頻度の高い順に並べた簡単なリストです。

- :mod:`pwnlib.context`
    .. - :data:`pwnlib.context.context`
     - Responsible for most of the pwntools convenience settings
     - Set `context.log_level = 'debug'` when troubleshooting your exploit
     - Scope-aware, so you can disable logging for a subsection of code via :meth:`.ContextType.local`

    - :data:`pwnlib.context.context`
    - pwntoolsの便利な設定のほとんどを担当する
    - エクスプロイトのトラブルシューティングを行う際に、 `context.log_level = 'debug'` を設定します。
    - スコープに対応しているので、 :meth:`.ContextType.local` でコードのサブセクションのログを無効にすることができます。
- ``remote``, ``listen``, ``ssh``, ``process``
    .. - :mod:`pwnlib.tubes`
     - Super convenient wrappers around all of the common functionality for CTF challenges
     - Connect to anything, anywhere, and it works the way you want it to
     - Helpers for common tasks like ``recvline``, ``recvuntil``, ``clean``, etc.
     - Interact directly with the application via ``.interactive()``

    - :mod:`pwnlib.tubes`
    - CTFチャレンジのための一般的な機能をすべて備えた超便利なラッパー
    - 何にでも、どこにでも接続でき、思い通りに動作します。
    - ``recvline``、 ``recvuntil``、 ``clean`` などの一般的なタスクのヘルパーです。
    - ``.interactive()`` でアプリケーションと直接対話することができます。
- ``p32`` and ``u32``
    .. - :mod:`pwnlib.util.packing`
     - Useful functions to make sure you never have to remember if ``'>'`` means signed or unsigned for ``struct.pack``, and no more ugly ``[0]`` index at the end.
     - Set ``signed`` and ``endian`` in sane manners (also these can be set once on ``context`` and not bothered with again)
     - Most common sizes are pre-defined (``u8``, ``u64``, etc), and :func:`pwnlib.util.packing.pack` lets you define your own.

    - :mod:`pwnlib.util.packing`
    - 便利な関数で、 ``struct.pack`` において ``'>'`` が符号付きなのか符号なしなのかを覚えておく必要がなくなり、最後に醜い ``[0]`` インデックスを付ける必要もなくなります。
    - ``signed`` と ``endian`` をまともな方法で設定することができます (これらは ``context`` で一度設定すれば二度と気にする必要はありません)。
    - ほとんどの一般的なサイズはあらかじめ定義されています(``u8``, ``u64``, 等)。 :func:`pwnlib.util.packing.pack` では自分で定義することができます。
- ``log``
    .. - :mod:`pwnlib.log`
    .. - Make your output pretty!

    - :mod:`pwnlib.log`
    - 綺麗に出力します！
- ``cyclic`` and ``cyclic_func``
    .. - :mod:`pwnlib.util.cyclic`
     - Utilities for generating strings such that you can find the offset of any given substring given only N (usually 4) bytes.  This is super useful for straight buffer overflows.  Instead of looking at 0x41414141, you could know that 0x61616171 means you control EIP at offset 64 in your buffer.

    - :mod:`pwnlib.util.cyclic`
    - Nバイト（通常は4バイト）だけで、任意の部分文字列のオフセットを見つけることができるような文字列を生成するユーティリティです。 これは、ストレートなバッファオーバーフローに非常に役立ちます。 0x41414141を見る代わりに、0x61616171がバッファのオフセット64でEIPを制御していることを知ることができます。
- ``asm`` and ``disasm``
    .. - :mod:`pwnlib.asm`
     - Quickly turn assembly into some bytes, or vice-versa, without mucking about
     - Supports any architecture for which you have a binutils installed
     - Over 20 different architectures have pre-built binaries at `ppa:pwntools/binutils <https://launchpad.net/~pwntools/+archive/ubuntu/binutils>`_.

    - :mod:`pwnlib.asm`
    - アセンブリをバイトに変換したり、その逆を行ったりすることが可能です。
    - binutilsがインストールされているすべてのアーキテクチャに対応
    - 20以上の異なるアーキテクチャでは、`ppa:pwntools/binutils <https://launchpad.net/~pwntools/+archive/ubuntu/binutils>`_ にビルド済みのバイナリが用意されています。
- ``shellcraft``
    .. - :mod:`pwnlib.shellcraft`
     - Library of shellcode ready to go
     - ``asm(shellcraft.sh())`` gives you a shell
     - Templating library for reusability of shellcode fragments

    - :mod:`pwnlib.shellcraft`
    - すぐに使えるシェルコードのライブラリ
    - ``asm(shellcraft.sh())`` でシェルを作成する
    - シェルコードの断片を再利用するためのテンプレートライブラリ
- ``ELF``
    .. - :mod:`pwnlib.elf`
    .. - ELF binary manipulation tools, including symbol lookup, virtual memory to file offset helpers, and the ability to modify and save binaries back to disk
    
    - :mod:`pwnlib.elf`
    - シンボルルックアップ、仮想メモリからファイルへのオフセットヘルパー、バイナリを修正してディスクに保存する機能など、ELFバイナリ操作ツール
- ``DynELF``
    .. - :mod:`pwnlib.dynelf`
    .. - Dynamically resolve functions given only a pointer to any loaded module, and a function which can leak data at any address

    - :mod:`pwnlib.dynelf`
    - ロードされたモジュールへのポインタのみが与えられた関数を動的に解決し、任意のアドレスのデータをリークできる関数
- ``ROP``
    .. - :mod:`pwnlib.rop`
    .. - Automatically generate ROP chains using a DSL to describe what you want to do, rather than raw addresses

    - :mod:`pwnlib.rop`
    - 生のアドレスではなく、やりたいことを記述するDSLを使ってROPチェーンを自動生成する
- ``gdb.debug`` and ``gdb.attach``
    .. - :mod:`pwnlib.gdb`
    .. - Launch a binary under GDB and pop up a new terminal to interact with it.  Automates setting breakpoints and makes iteration on exploits MUCH faster.
    .. - Alternately, attach to a running process given a PID, :mod:`pwnlib.tubes` object, or even just a socket that's connected to it

    - :mod:`pwnlib.gdb`
    - GDBでバイナリを起動し、それを操作するための新しいターミナルを表示します。 ブレークポイントの設定が自動化され、エクスプロイトの反復作業が非常に速くなります。
    - 別の方法として、PIDや :mod:`pwnlib.tube` オブジェクト、あるいは単に接続されているソケットを使って、実行中のプロセスにアタッチすることもできます。
- ``args``
    .. - Dictionary containing all-caps command-line arguments for quick access
    .. - Run via ``python foo.py REMOTE=1`` and ``args['REMOTE'] == '1'``.
    .. - Can also control logging verbosity and terminal fanciness

    - 大文字のコマンドライン引数を含む辞書で、素早くアクセスできます。
    - ``python foo.py REMOTE=1`` かつ ``args['REMOTE'] == '1'`` で実行します。
    - また、ログの冗長性やターミナルの見栄えをコントロールすることもできます。
        - `NOTERM`
        - `SILENT`
        - `DEBUG`
- ``randoms``, ``rol``, ``ror``, ``xor``, ``bits``
    .. - :mod:`pwnlib.util.fiddling`
    .. - Useful utilities for generating random data from a given alphabet, or simplifying math operations that usually require masking off with `0xffffffff` or calling `ord` and `chr` an ugly number of times

    - :mod:`pwnlib.util.fiddling`
    - 与えられたアルファベットからランダムなデータを生成したり、通常は `0xffffffff` でマスクしたり、`ord` や `chr` を何度も呼び出したりする必要のある数学演算を簡略化したりするのに便利なユーティリティです。
- ``net``
    .. - :mod:`pwnlib.util.net`
    .. - Routines for querying about network interfaces

    - :mod:`pwnlib.util.net`
    - ネットワーク・インターフェイスを照会するためのルーチン
- ``proc``
    .. - :mod:`pwnlib.util.proc`
    .. - Routines for querying about processes

    - :mod:`pwnlib.util.proc`
    - プロセスを照会するためのルーチン
- ``pause``
    .. - It's the new ``getch``

    - 新しい ``getch`` です。
- ``safeeval``
    .. - :mod:`pwnlib.util.safeeval`
    .. - Functions for safely evaluating python code without nasty side-effects.

    - :mod:`pwnlib.util.safeeval`
    - 厄介な副作用なしにpythonコードを安全に評価するための関数です。

.. These are all pretty self explanatory, but are useful to have in the global namespace.

これらはすべて自明のことですが、グローバルな名前空間にあると便利です。

- ``hexdump``
- ``read`` and ``write``
- ``enhex`` and ``unhex``
- ``more``
- ``group``
- ``align`` and ``align_down``
- ``urlencode`` and ``urldecode``
- ``which``
- ``wget``

.. Additionally, all of the following modules are auto-imported for you.  You were going to do it anyway.

さらに、以下のすべてのモジュールが自動インポートされます。どうせやるでしょう。

- ``os``
- ``sys``
- ``time``
- ``requests``
- ``re``
- ``random``
