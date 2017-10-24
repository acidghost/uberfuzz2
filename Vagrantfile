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
  config.vm.provision "file", source: "../vuzzer-64bit", destination: "vuzzer"
  config.vm.provision "file", source: "../vuzzer-symbex", destination: "vuzzer-symbex"
  config.vm.provision "file", source: "../fuzz-test", destination: "fuzz-test"

  config.vm.provision "main", type: "shell", inline: <<-SHELL
    apt-get update
    apt-get install -y g++ git cmake3 pkg-config automake autoconf libtool \
      libzmq3-dev python python-pip libdwarf-dev libelf-dev libssl-dev \
      libpng-dev python-dev libffi-dev build-essential

    pip install -U pip setuptools
    pip install --upgrade --force-reinstall angr angr-utils bitvector
    pip install -I --no-binary :all: capstone

    # install custom deps in /opt
    pushd /opt

    # install cpputest (required by Collections-C)
    if [ ! -f "/usr/local/lib/libCppUTest.a" ]; then
      rm -rf cpputest
      git clone --depth 1 git://github.com/cpputest/cpputest.git
      cd cpputest/cpputest_build
      autoreconf .. -i
      ../configure
      make
      make install
      cd ../../
    else
      echo "cpputest already installed"
    fi

    # install Collections-C (required by driver's code)
    if [ ! -f "/usr/local/lib/libcollectc.a" ]; then
      rm -rf Collections-C
      git clone --depth 1 https://github.com/srdja/Collections-C.git
      cd Collections-C
      mkdir build
      cd build
      CFLAGS=-std=c99 cmake ..
      make
      make install
    else
      echo "Collections-C already installed"
    fi

    # install EWAHBoolArray
    if [ ! -d EWAHBoolArray ]; then
      git clone --depth 1 https://github.com/lemire/EWAHBoolArray.git
    fi
    cp EWAHBoolArray/headers/* /usr/include

    popd
  SHELL

  config.vm.provision "vuzzer", type: "shell", privileged: false, inline: <<-SHELL
    pindir=pin-2.14-71313-gcc.4.4.7-linux
    pinzip=$pindir.tar.gz
    if [ ! -d $pindir ]; then
      wget -q http://software.intel.com/sites/landingpage/pintool/downloads/$pinzip
    fi
    tar xzf $pinzip
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

  config.vm.provision "suts", type: "shell", privileged: false, inline: <<-SHELL
    # get and build gif2png
    if [ ! -d gif2png ]; then
      git clone --depth 1 https://gitlab.com/esr/gif2png.git
    fi
    cd gif2png
    make clean gif2png
    cd ..
  SHELL
end
