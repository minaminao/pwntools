pwntools
====================================

.. ``pwntools`` is a CTF framework and exploit development library.
 Written in Python, it is designed for rapid prototyping and development,
 and intended to make exploit writing as simple as possible.

``pwntools`` は、CTFフレームワークとエクスプロイト開発ライブラリです。Pythonで書かれており、ラピッドプロトタイピングと開発のために設計されており、エクスプロイトの作成を可能な限り簡単にすることを目的としています。

.. The primary location for this documentation is at docs.pwntools.com_, which uses
 readthedocs_. It comes in three primary flavors:

このドキュメントの主な場所は docs.pwntools.com_ で、readthedocs_ を使用しています。これは3つの主要な種類があります。

- Stable_
- Beta_
- Dev_

.. _readthedocs: https://readthedocs.org
.. _docs.pwntools.com: https://docs.pwntools.com
.. _Stable: https://docs.pwntools.com/en/stable
.. _Beta: https://docs.pwntools.com/en/beta
.. _Dev: https://docs.pwntools.com/en/dev


Getting Started
---------------

.. toctree::
   :maxdepth: 3
   :glob:

   about
   install
   intro
   globals
   commandline


Module Index
------------

Each of the ``pwntools`` modules is documented here.

.. toctree::
   :maxdepth: 1
   :glob:

   adb
   args
   asm
   atexception
   atexit
   constants
   config
   context
   dynelf
   encoders
   elf/*
   exception
   filepointer
   filesystem
   flag
   fmtstr
   gdb
   libcdb
   log
   memleak
   protocols
   qemu
   replacements
   rop/*
   runner
   shellcraft
   shellcraft/*
   term
   timeout
   tubes
   tubes/*
   ui
   update
   useragents
   util/*

.. toctree::
   :hidden:

   testexample
   rop/call

.. only:: not dash

   Indices and tables
   ==================

   * :ref:`genindex`
   * :ref:`modindex`
   * :ref:`search`

Bytes
-----

.. The bytes vs text distinction is so important that it even made it to this main page.
 See the pwntools-tutorial_ repo for the latest tutorial finally
 explaining the difference once and for all (hopefully).

バイトとテキストの区別はとても重要なので、このメインページにも書かれています。最新のチュートリアルは pwntools-tutorial_ repoを参照してください。

.. _pwntools-tutorial: https://github.com/Gallopsled/pwntools-tutorial/blob/master/bytes.md
