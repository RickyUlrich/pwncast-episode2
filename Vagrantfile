# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  config.vm.box = "bento/debian-9.5"
  # config.vm.box = "bento/ubuntu-18.04"

  # set memory limit
  config.vm.provider "virtualbox" do |vb|
    vb.customize ["modifyvm", :id, "--memory", "2024"]
    vb.customize ["modifyvm", :id, "--cpus", "2"]
  end

  # alway pull updates on startup
  config.vm.provision "shell", run: "always", inline: <<-SHELL
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y && apt-get upgrade -y && apt-get autoremove -y
    echo 0 | tee /proc/sys/kernel/randomize_va_space
  SHELL

  # provision/config
  config.vm.provision "shell", inline: <<-SHELL
    export DEBIAN_FRONTEND=noninteractive

    apt-get update -y && apt-get upgrade -y

    # random tools stuff
    apt-get install -y netcat git cmake exuberant-ctags
    apt-get install -y build-essential tmux vim valgrind bc strace
    apt-get install -y software-properties-common python3 python3-pip python-pip

    # pwntools stuff
    apt-get install -y python2.7 python-pip python-dev git libssl-dev libffi-dev build-essential
    python -m pip install --upgrade pip
    python -m pip install --upgrade pwntools

    # i386 stuff
    dpkg --add-architecture i386
    apt-get update -y
    apt-get install -y libc6:i386 libncurses5:i386 libstdc++6:i386 lib32z1
  SHELL

end
