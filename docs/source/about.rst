About pwntools
========================

.. Whether you're using it to write exploits, or as part
 of another software project will dictate how you use it.

エクスプロイトを書くために使っているのか、他のソフトウェアプロジェクトの一部として使っているのかによって、使い方が変わってきます。

.. Historically pwntools was used as a sort of exploit-writing DSL. Simply doing
 ``from pwn import *`` in a previous version of pwntools would bring all sorts of
 nice side-effects.

歴史的に、pwntoolsはエクスプロイトを書くDSLのようなものとして使われていました。以前のバージョンのpwntoolsで ``from pwn import *`` を実行するだけで、あらゆる種類の素晴らしい副作用をもたらしました。

.. When redesigning pwntools for 2.0, we noticed two contrary goals:

2.0のためにpwntoolsを再設計するとき、私たちは2つの対照的な目標に気づきました。

.. * We would like to have a "normal" python module structure, to allow other
  people to familiarize themselves with pwntools quickly.

* 他の人がすぐにpwntoolsに慣れることができるように、「普通の」pythonモジュール構造にしたいと思っています。

.. * We would like to have even more side-effects, especially by putting the
  terminal in raw-mode.

* 特にターミナルをraw-modeにすることで、さらに多くの副作用を持たせたいと考えています。

.. To make this possible, we decided to have two different modules. :mod:`pwnlib`
 would be our nice, clean Python module, while :mod:`pwn` would be used during
 CTFs.

これを可能にするために、私たちは2つの異なるモジュールを用意することにしました。 :mod:`pwnlib` は美しくクリーンなPythonモジュールで、一方 :mod:`pwn` はCTFの際に使用されます。

:mod:`pwn` --- Toolbox optimized for CTFs
-----------------------------------------

.. module:: pwn

.. As stated, we would also like to have the ability to get a lot of these
 side-effects by default. That is the purpose of this module. It does
 the following:

先に述べたように、これらの副作用の多くをデフォルトで得られるような機能も欲しいところです。それがこのモジュールの目的です。このモジュールは以下のことを行います。

.. * Imports everything from the toplevel :mod:`pwnlib` along with
  functions from a lot of submodules. This means that if you do
  ``import pwn`` or ``from pwn import *``, you will have access to
  everything you need to write an exploit.
 * Calls :func:`pwnlib.term.init` to put your terminal in raw mode
  and implements functionality to make it appear like it isn't.
 * Setting the :data:`pwnlib.context.log_level` to `"info"`.
 * Tries to parse some of the values in :data:`sys.argv` and every
  value it succeeds in parsing it removes.

* トップレベルの :mod:`pwnlib` からすべてを、多くのサブモジュールからの関数とともにインポートします。これは、 ``import pwn`` または ``from pwn import *`` を実行すると、エクスプロイトを書くのに必要なすべてのものにアクセスできることを意味しています。
* ターミナルをrawモードにするために :func:`pwnlib.term.init` を呼び出し、rawモードでないように見せる機能を実装しています。
* :data:`pwnlib.context.log_level` を `"info"` に設定します。
* :data:`sys.argv` の中のいくつかの値を解析しようとし、解析に成功したすべての値を削除します。

:mod:`pwnlib` --- Normal python library
---------------------------------------

.. module:: pwnlib

.. This module is our "clean" python-code. As a rule, we do not think that
 importing :mod:`pwnlib` or any of the submodules should have any significant
 side-effects (besides e.g. caching).

このモジュールは私たちの「クリーン」なPythonコードです。原則として、 :mod:`pwnlib` やサブモジュールをインポートしても、(キャッシュなどの他に)重要な副作用があるとは考えていません。

.. For the most part, you will also only get the bits you import. You for instance would
 not get access to :mod:`pwnlib.util.packing` simply by doing ``import
 pwnlib.util``.

ほとんどの場合、インポートした部分だけを得ることができます。例えば、 ``import pwnlib.util`` を実行しただけでは、 :mod:`pwnlib.util.packing` へのアクセスは得られません。

.. Though there are a few exceptions (such as :mod:`pwnlib.shellcraft`), that does
 not quite fit the goals of being simple and clean, but they can still be
 imported without implicit side-effects.

いくつかの例外(例えば :mod:`pwnlib.shellcraft`)がありますが、これはシンプルでクリーンであるという目的には合致しませんが、暗黙の副作用なしにインポートすることができます。
