.. testsetup:: *

   from pwn import *
   import logging
   log = pwnlib.log.getLogger('pwnlib.context')
   context.clear()

:mod:`pwnlib.context` --- Setting runtime variables
=====================================================

.. Many settings in ``pwntools`` are controlled via the global variable :data:`.context`, such as the selected target operating system, architecture, and bit-width.

pwntools``の多くの設定は、グローバル変数 :data:`.context` を通して制御されます。例えば、選択されたターゲットのオペレーティングシステム、アーキテクチャ、ビット幅などです。

.. In general, exploits will start with something like:

一般的に、エクスプロイトは次のような内容で始まります。

.. code-block:: python

    from pwn import *
    context.arch = 'amd64'

.. Which sets up everything in the exploit for exploiting a 64-bit Intel binary.

これにより、64ビットのインテル製バイナリを悪用するためのエクスプロイトのすべてが設定されます。

.. The recommended method is to use ``context.binary``  to automagically set all of the appropriate values.

推奨される方法は、 ``context.binary`` を使用して、適切な値を自動的に設定することです。

.. code-block:: python

    from pwn import *
    context.binary = './challenge-binary'

Module Members
----------------------------------------------------

.. automodule:: pwnlib.context
   :members:
