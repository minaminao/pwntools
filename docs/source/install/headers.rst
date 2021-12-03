Python Development Headers
-----------------------------

.. Some of pwntools' Python dependencies require native extensions (for example, Paramiko requires PyCrypto).
.. 
.. In order to build these native extensions, the development headers for Python must be installed.

pwntoolsのPythonの依存関係の中には、ネイティブ拡張を必要とするものがあります（例えば、ParamikoはPyCryptoを必要とします）。

これらのネイティブエクステンションをビルドするためには、Python用の開発ヘッダーをインストールする必要があります。

Ubuntu
^^^^^^^^^^^^^^^^

.. code-block:: bash

    $ apt-get install python-dev

Mac OS X
^^^^^^^^^^^^^^^^

No action needed.