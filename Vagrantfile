# -*- mode: ruby -*-
# vi: set ft=ruby :

# All Vagrant configuration is done below. The "2" in Vagrant.configure
# configures the configuration version (we support older styles for
# backwards compatibility). Please don't change it unless you know what
# you're doing.
Vagrant.configure("2") do |config|
  # The most common configuration options are documented and commented below.
  # For a complete reference, please see the online documentation at
  # https://docs.vagrantup.com.

  # Every Vagrant development environment requires a box. You can search for
  # boxes at https://vagrantcloud.com/search.
  config.vm.box = "ubuntu/trusty64"

  # Disable automatic box update checking. If you disable this, then
  # boxes will only be checked for updates when the user runs
  # `vagrant box outdated`. This is not recommended.
  # config.vm.box_check_update = false

  # Create a forwarded port mapping which allows access to a specific port
  # within the machine from a port on the host machine. In the example below,
  # accessing "localhost:8080" will access port 80 on the guest machine.
  # NOTE: This will enable public access to the opened port
  # config.vm.network "forwarded_port", guest: 80, host: 8080

  # Create a forwarded port mapping which allows access to a specific port
  # within the machine from a port on the host machine and only allow access
  # via 127.0.0.1 to disable public access
  # config.vm.network "forwarded_port", guest: 80, host: 8080, host_ip: "127.0.0.1"

  # Create a private network, which allows host-only access to the machine
  # using a specific IP.
  # config.vm.network "private_network", ip: "192.168.33.10"

  # Create a public network, which generally matched to bridged network.
  # Bridged networks make the machine appear as another physical device on
  # your network.
  # config.vm.network "public_network"

  # Share an additional folder to the guest VM. The first argument is
  # the path on the host to the actual folder. The second argument is
  # the path on the guest to mount the folder. And the optional third
  # argument is a set of non-required options.
  # config.vm.synced_folder "../data", "/vagrant_data"

  # Provider-specific configuration so you can fine-tune various
  # backing providers for Vagrant. These expose provider-specific options.
  # Example for VirtualBox:
  #
  # config.vm.provider "virtualbox" do |vb|
  #   # Display the VirtualBox GUI when booting the machine
  #   vb.gui = true
  #
  #   # Customize the amount of memory on the VM:
  #   vb.memory = "1024"
  # end
  #
  # View the documentation for the provider you are using for more
  # information on available options.
  config.vm.provider "virtualbox" do |vb|
    vb.memory = "2048"
  end

  # Enable provisioning with a shell script. Additional provisioners such as
  # Puppet, Chef, Ansible, Salt, and Docker are also available. Please see the
  # documentation for more information about their specific syntax and use.
  config.vm.provision "pin", type: "file",
                          source: "../pin-2.13-62732-gcc.4.4.7-linux.tar.gz",
                          destination: "pin-2.13-62732-gcc.4.4.7-linux.tar.gz"
  config.vm.provision "vu-file", type: "file",
                      source: "../vuzzer-64bit", destination: "vuzzer"

  config.vm.provision "vu-pickles", type: "file",
                      source: "../vuzzer-pickles", destination: "vuzzer-pickles"

  config.vm.provision "testcases", type: "file",
                      source: "../testcases", destination: "testcases"

  config.vm.synced_folder "work/vuzzer", "/work"

  config.vm.provision "main", type: "shell", inline: <<-SHELL
    apt-get update
    apt-get install -y g++ git python build-essential
    # vuzzer/libdft64 requirements
    apt-get install -y python-pip libdwarf-dev libelf-dev libssl-dev
    # libjpeg-turbo requirements
    apt-get install -y autoconf automake libtool nasm
    # libming requirements
    apt-get install -y flex bison libfreetype6 libfreetype6-dev

    pip install -U pip setuptools
    pip install --upgrade --force-reinstall bitvector

    # install custom deps in /opt
    pushd /opt

    # install EWAHBoolArray
    if [ ! -d EWAHBoolArray ]; then
      git clone --depth 1 https://github.com/lemire/EWAHBoolArray.git
    fi
    cp EWAHBoolArray/headers/* /usr/include

    popd
  SHELL

  config.vm.provision "vuzzer", type: "shell", privileged: false, inline: <<-SHELL
    pindir=pin-2.13-62732-gcc.4.4.7-linux
    if [[ ! -d $pindir ]]; then
      tar xzf $pindir.tar.gz
    fi
    export PIN_ROOT=$HOME/$pindir
    export PIN_HOME=$HOME/$pindir
    # install vuzzer
    cd vuzzer
    export DFT_HOME=$(pwd)/libdft64
    cd fuzzer-code
    echo "making bbcounts pintool..."
    make -f mymakefile clean tools
    echo "done making bbcounts pintool"
    cd ../libdft64
    echo "making libdft"
    make clean
    make
    make tools
    echo "done making libdft"
    cd ..
  SHELL

  config.vm.provision "vu-setup", type: "shell", inline: <<-SHELL
    echo 0 | tee /proc/sys/kernel/randomize_va_space
    echo 0 | tee /proc/sys/kernel/yama/ptrace_scope
    mount -t tmpfs -o size=1024M tmpfs vuzzer/fuzzer-code/vutemp
    rm -rf /home/vagrant/.vuenv
    echo "export PIN_ROOT=/home/vagrant/pin-2.13-62732-gcc.4.4.7-linux" >> /home/vagrant/.vuenv
    echo "export VUZZER_ROOT=/home/vagrant/vuzzer" >> /home/vagrant/.vuenv
  SHELL

  config.vm.provision "vu-restore", type: "shell", inline: <<-SHELL
    echo 1 | tee /proc/sys/kernel/randomize_va_space
    echo 1 | tee /proc/sys/kernel/yama/ptrace_scope
    umount vuzzer/fuzzer-code/vutemp
    rm -rf /home/vagrant/.vuenv
  SHELL

  config.vm.provision "suts", type: "shell", privileged: false, inline: <<-SHELL
    if [[ ! -d libjpeg-turbo-1.5.1 ]]; then
      wget -nv https://github.com/libjpeg-turbo/libjpeg-turbo/archive/1.5.1.tar.gz
      tar -xzf 1.5.1.tar.gz
      rm 1.5.1.tar.gz

      cd libjpeg-turbo-1.5.1/
      autoreconf -fiv
      cd release
      sh ../configure LDFLAGS=-static && make
      cd ~
    fi

    if [[ ! -d libpng-1.6.29 ]]; then
      wget -nv https://github.com/acidghost/libpng/archive/v1.6.29-uberfuzz1.tar.gz
      tar -zxf v1.6.29-uberfuzz1.tar.gz
      rm v1.6.29-uberfuzz1.tar.gz
      mv libpng-1.6.29-uberfuzz1 libpng-1.6.29

      cd libpng-1.6.29
      cp scripts/pnglibconf.h.prebuilt pnglibconf.h
      cp scripts/makefile.linux makefile
      make test
      cd contrib/libtests
      gcc -O3 -Wall readpng.c -o readpng ../../libpng.a -lz -lm
      cd ~
    fi

    if [[ ! -d binutils-2.28 ]]; then
      wget -nv https://ftp.gnu.org/gnu/binutils/binutils-2.28.tar.gz
      tar -xzf binutils-2.28.tar.gz
      rm binutils-2.28.tar.gz

      cd binutils-2.28
      ./configure
      make
      cd ~
    fi

    if [[ ! -d tiff-4.0.9 ]]; then
      wget -nv ftp://download.osgeo.org/libtiff/tiff-4.0.9.tar.gz
      tar -xzf tiff-4.0.9.tar.gz
      rm tiff-4.0.9.tar.gz

      cd tiff-4.0.9
      ./configure --enable-static
      make LDFLAGS=-static
      cd ~
    fi

    if [[ ! -d libming-ming-0_4_8 ]]; then
      wget -nv https://github.com/libming/libming/archive/ming-0_4_8.tar.gz
      tar -xzf ming-0_4_8.tar.gz
      rm ming-0_4_8.tar.gz

      cd libming-ming-0_4_8
      ./autogen.sh
      ./configure --enable-static
      make LDFLAGS=-static
      cd ~
    fi
  SHELL
end
