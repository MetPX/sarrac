# Flow Test Autoconfig
#
# Script not meant to be run on personal machines (may break some configs)
# Intended use case is a fresh sys (tested on ubuntu18.04desktop)
# which can easily be run in a virtualbox VM.

# Install and configure dependencies
sudo apt-key adv --keyserver "hkps.pool.sks-keyservers.net" --recv-keys "0x6B73A36E6026DFCA"
sudo add-apt-repository -y ppa:ssc-hpc-chp-spc/metpx-daily
sudo apt-get update
sudo apt -y install python3-setuptools
sudo apt -y install erlang-nox erlang-diameter erlang-eldap findutils git librabbitmq4 net-tools openssh-client openssh-server python3-pip rabbitmq-server xattr wget 
sudo apt -y install librabbitmq4 librabbitmq-dev libssl-dev libjson-c-dev valgrind

pip3 install -U pip
pip3 install metpx-sr3[amqp,mqtt,vip,ftppoll]
pip3 install pyftpdlib paramiko net-tools

# The dependencies that are installed using apt are only available to system default Python versions (e.g. Python 3.8 on Ubuntu 20.04)
# If we are testing on a non-default Python version, we need to ensure these dependencies are still installed, so we use pip.
# See issue #407, #445.
for PKG in amqp appdirs dateparser watchdog netifaces humanize jsonpickle paho-mqtt psutil xattr ; do
    PKG_INSTALLED="`pip3 list | grep ${PKG}`"
    if [ "$?" == "0" ] ; then
        echo "$PKG is already installed"
    else
        pip3 install ${PKG}
    fi
done

# Setup basic configs
mkdir -p ~/.config/sr3

cat > ~/.config/sr3/default.conf << EOF
expire 7h
declare env FLOWBROKER=localhost
declare env SFTPUSER=${USER}
declare env TESTDOCROOT=${HOME}/sarra_devdocroot
declare env MQP=amqp
declare env several=3
logEvents after_accept,after_work,on_housekeeping,post,after_post
EOF

ADMIN_PASSWORD=$(openssl rand -hex 6)
OTHER_PASSWORD=$(openssl rand -hex 6)
cat > ~/.config/sr3/credentials.conf << EOF
amqp://bunnymaster:${ADMIN_PASSWORD}@localhost
amqp://tsource:${OTHER_PASSWORD}@localhost
amqp://tsub:${OTHER_PASSWORD}@localhost
amqp://tfeed:${OTHER_PASSWORD}@localhost
amqp://anonymous:${OTHER_PASSWORD}@localhost
amqps://anonymous:anonymous@dd.weather.gc.ca
amqps://anonymous:anonymous@dd1.weather.gc.ca
amqps://anonymous:anonymous@dd2.weather.gc.ca
amqps://anonymous:anonymous@hpfx.collab.science.gc.ca
ftp://anonymous:anonymous@localhost:2121/
EOF

cat > ~/.config/sr3/admin.conf << EOF
cluster localhost
admin amqp://bunnymaster@localhost
feeder amqp://tfeed@localhost
declare source tsource
declare subscriber tsub
declare subscriber anonymous
EOF

echo "pwd is: `pwd`"

check_wsl=$(ps --no-headers -o comm 1)

# Manage RabbitMQ
if [[ $(($check_wsl == "init" )) ]]; then
	sudo service rabbitmq-server restart
else
	sudo systemctl restart rabbitmq-server
fi
sudo rabbitmq-plugins enable rabbitmq_management

sudo rabbitmqctl delete_user guest

for USER_NAME in "bunnymaster" "tsource" "tsub" "tfeed" "anonymous"; do
sudo rabbitmqctl delete_user ${USER_NAME}
done

sudo rabbitmqctl add_user bunnymaster ${ADMIN_PASSWORD}
sudo rabbitmqctl set_permissions bunnymaster ".*" ".*" ".*"
sudo rabbitmqctl set_user_tags bunnymaster administrator

echo

if [[ $(($check_wsl == "init" )) ]]; then
	sudo service rabbitmq-server restart
else 
	sudo systemctl restart rabbitmq-server
fi

pushd /usr/local/bin
sudo mv rabbitmqadmin rabbitmqadmin.1
sudo wget http://localhost:15672/cli/rabbitmqadmin
sudo chmod 755 rabbitmqadmin
popd 
hash -r 
echo "rabbitmqadmin is: `which rabbitmqadmin`"

mkdir -p ~/.config/sr3/cpost

BROKER=amqp://tfeed@localhost
EXCHANGE=xs_feed

cat >~/.config/sr3/cpost/local_post.conf  <<EOT

post_broker ${BROKER}
post_exchange ${EXCHANGE}

vip 127.0.0.1
realpath off
logReject on
logLevel debug
debug True
exchangeDeclare True
#integrity none
shim_post_minterval 10
#shim_skip_parent_open_files
#shim_post_once
#shim_defer_posting_to_exit
expire 1d
nodupe_ttl 0
header toto=pig
events modify,link,delete

post_baseUrl file:`pwd`/shim_dirA
post_baseDir `pwd`/shim_dirA
post_topicPrefix v03.post

accept .*
EOT

#cp local_post.conf ~/.config/sr3/cpost

# Configure users
echo "about to sr3 declare"
sr3 --debug --users declare
echo "done sr3 declare"
