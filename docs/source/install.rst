Installation
============

.. Pwntools is best supported on 64-bit Ubuntu LTS releases (14.04, 16.04, 18.04, and 20.04).  Most functionality should work on any Posix-like distribution (Debian, Arch, FreeBSD, OSX, etc.).

Pwntoolsは、64ビットのUbuntu LTSリリース（14.04、16.04、18.04、20.04）で最もよくサポートされています。 ほとんどの機能は、あらゆるPosix系ディストリビューション（Debian、Arch、FreeBSD、OSXなど）で動作するはずです。

Prerequisites
-------------

.. In order to get the most out of ``pwntools``, you should have the
 following system libraries installed.

``pwntools`` を最大限に活用するためには、以下のシステムライブラリがインストールされている必要があります。

.. toctree::
   :maxdepth: 3
   :glob:

   install/*

Released Version
-----------------

pwntools is available as a ``pip`` package for both Python2 and Python3.

Python3
^^^^^^^

.. code-block:: bash

    $ apt-get update
    $ apt-get install python3 python3-pip python3-dev git libssl-dev libffi-dev build-essential
    $ python3 -m pip install --upgrade pip
    $ python3 -m pip install --upgrade pwntools


Python2 (Deprecated)
^^^^^^^^^^^^^^^^^^^^

NOTE: Pwntools maintainers STRONGLY recommend using Python3 for all future Pwntools-based scripts and projects.

Additionally, due to `pip` dropping support for Python2, a specfic version of `pip` must be installed.

.. code-block:: bash

    $ apt-get update
    $ apt-get install python python-pip python-dev git libssl-dev libffi-dev build-essential
    $ python2 -m pip install --upgrade pip==20.3.4
    $ python2 -m pip install --upgrade pwntools


Command-Line Tools
------------------

.. When installed with ``sudo`` the above commands will install Pwntools' command-line tools to somewhere like ``/usr/bin``.

.. However, if you run as an unprivileged user, you may see a warning message that looks like this:

``sudo`` でインストールすると、上記のコマンドはPwntoolsのコマンドラインツールを ``/usr/bin`` のような場所にインストールします。

しかし、非特権ユーザーとして実行した場合、以下のような警告メッセージが表示されることがあります。

.. code-block::

      WARNING: The scripts asm, checksec, common, constgrep, cyclic, debug, disablenx, disasm, 
      elfdiff, elfpatch, errno, hex, main, phd, pwn, pwnstrip, scramble, shellcraft, template, 
      unhex, update and version are installed in '/home/user/.local/bin' which is not on PATH.

Follow the instructions listed and add ``~/.local/bin`` to your ``$PATH`` environment variable.

Development
--------------

.. If you are hacking on Pwntools locally, you'll want to do something like this:

ローカルでPwntoolsをハックしている場合は、以下のようにしてください。

.. code-block:: bash

    $ git clone https://github.com/Gallopsled/pwntools
    $ pip install --upgrade --editable ./pwntools

.. _Ubuntu: https://launchpad.net/~pwntools/+archive/ubuntu/binutils
