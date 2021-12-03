Binutils
-------------

.. Assembly of foreign architectures (e.g. assembling Sparc shellcode on
.. Mac OS X) requires cross-compiled versions of ``binutils`` to be
.. installed. We've made this process as smooth as we can.
.. 
.. In these examples, replace ``$ARCH`` with your target architecture (e.g., arm, mips64, vax, etc.).
.. 
.. Building `binutils` from source takes about 60 seconds on a modern 8-core machine.

海外のアーキテクチャのアセンブル（例：Mac OS X上でのSparcシェルコードのアセンブル）には、クロスコンパイルされたバージョンの ``binutils`` のインストールが必要です。私たちはこのプロセスをできる限りスムーズにしました。

これらの例では、 ``$ARCH`` をターゲットのアーキテクチャに置き換えてください (例: arm, mips64, vax など)。

ソースからの `binutils` のビルドは、最新の 8 コアマシンで約 60 秒かかります。

Ubuntu
^^^^^^^^^^^^^^^^

.. For Ubuntu 12.04 through 15.10, you must first add the pwntools `Personal Package Archive repository <https://launchpad.net/~pwntools/+archive/ubuntu/binutils>`__.
.. 
.. Ubuntu Xenial (16.04) has official packages for most architectures, and does not require this step.

Ubuntu 12.04~15.10の場合は、まずpwntoolsの `Personal Package Archive repository <https://launchpad.net/~pwntools/+archive/ubuntu/binutils>`__ を追加する必要があります。

Ubuntu Xenial（16.04）では、ほとんどのアーキテクチャに対応した公式パッケージが用意されており、この手順は必要ありません。

.. code-block:: bash

    $ apt-get install software-properties-common
    $ apt-add-repository ppa:pwntools/binutils
    $ apt-get update

.. Then, install the binutils for your architecture.

次に、お使いのアーキテクチャに対応したbinutilsをインストールします。

.. code-block:: bash

    $ apt-get install binutils-$ARCH-linux-gnu

Mac OS X
^^^^^^^^^^^^^^^^

.. Mac OS X is just as easy, but requires building binutils from source.
.. However, we've made ``homebrew`` recipes to make this a single command.
.. After installing `brew <http://brew.sh>`__, grab the appropriate
.. recipe from our `binutils
.. repo <https://github.com/Gallopsled/pwntools-binutils/>`__.

Mac OS Xの場合も同様に簡単ですが、ソースからbinutilsをビルドする必要があります。しかし、私たちは ``homebrew`` のレシピを作成して、これを一つのコマンドで行えるようにしました。 `brew <http://brew.sh>`__ をインストールした後、 `binutils repo <https://github.com/Gallopsled/pwntools-binutils/>`__ のレシピから適切なレシピを取得してください。

.. code-block:: bash

    $ brew install https://raw.githubusercontent.com/Gallopsled/pwntools-binutils/master/macos/binutils-$ARCH.rb

Alternate OSes
^^^^^^^^^^^^^^^^

.. If you want to build everything by hand, or don't use any of the above
.. OSes, ``binutils`` is simple to build by hand.

すべてを手作業で構築したい場合や、上記のOSを使用していない場合は、 ``binutils`` は手作業で構築するのが簡単です。

.. code-block:: bash

    #!/usr/bin/env bash

    V=2.25   # Binutils Version
    ARCH=arm # Target architecture

    cd /tmp
    wget -nc https://ftp.gnu.org/gnu/binutils/binutils-$V.tar.gz
    wget -nc https://ftp.gnu.org/gnu/binutils/binutils-$V.tar.gz.sig

    gpg --keyserver keys.gnupg.net --recv-keys 4AE55E93
    gpg --verify binutils-$V.tar.gz.sig

    tar xf binutils-$V.tar.gz

    mkdir binutils-build
    cd binutils-build

    export AR=ar
    export AS=as

    ../binutils-$V/configure \
        --prefix=/usr/local \
        --target=$ARCH-unknown-linux-gnu \
        --disable-static \
        --disable-multilib \
        --disable-werror \
        --disable-nls

    MAKE=gmake
    hash gmake || MAKE=make

    $MAKE -j clean all
    sudo $MAKE install

