#!/bin/bash

function check_install {
	if [ -z "`which "$1" 2>/dev/null`" ]
	then
		executable=$1
		shift
		while [ -n "$1" ]
		do
			DEBIAN_FRONTEND=noninteractive apt-get -q -y --force-yes install "$1"
			print_info "$1 installed for $executable"
			shift
		done
	else
		print_warn "$2 already installed"
	fi
}

function check_remove {
	if [ -n "`which "$1" 2>/dev/null`" ]
	then
		DEBIAN_FRONTEND=noninteractive apt-get -q -y --force-yes remove --purge "$2"
		print_info "$2 removed"
	else
		print_warn "$2 is not installed"
	fi
}

function check_sanity {
	# Do some sanity checking.
	if [ $(/usr/bin/id -u) != "0" ]
	then
		die 'Must be run by root user'
	fi

	if [ ! -f /etc/debian_version ]
	then
		die "Distribution is not supported"
	fi
}

function die {
	echo "ERROR: $1" > /dev/null 1>&2
	exit 1
}

function get_domain_name() {
	# Getting rid of the lowest part.
	domain=${1%.*}
	lowest=`expr "$domain" : '.*\.\([a-z][a-z]*\)'`
	case "$lowest" in
	com|net|org|gov|edu|co|me|info|name)
		domain=${domain%.*}
		;;
	esac
	lowest=`expr "$domain" : '.*\.\([a-z][a-z]*\)'`
	[ -z "$lowest" ] && echo "$domain" || echo "$lowest"
}

function get_password() {
	# Check whether our local salt is present.
	SALT=/var/lib/random_salt
	if [ ! -f "$SALT" ]
	then
		head -c 512 /dev/urandom > "$SALT"
		chmod 400 "$SALT"
	fi
	password=`(cat "$SALT"; echo $1) | md5sum | base64`
	echo ${password:0:13}
}

function print_info {
	echo -n -e '\e[1;36m'
	echo -n $1
	echo -e '\e[0m'
}

function print_warn {
	echo -n -e '\e[1;33m'
	echo -n $1
	echo -e '\e[0m'
}


## Installation of Applications


function install_dash {
	check_install dash dash
	rm -f /bin/sh
	ln -s dash /bin/sh
}

function install_nano {
	check_install nano nano
}

function install_htop {
	check_install htop htop
}

function install_mc {
	check_install mc mc
}

function install_iotop {
	check_install iotop iotop
}

function install_iftop {
	check_install iftop iftop
	print_warn "Run IFCONFIG to find your net. device name"
	print_warn "Example usage: iftop -i venet0"
}

function install_vim {
	check_install vim vim
}

function install_dash {
	check_install dash dash
	rm -f /bin/sh
	ln -s dash /bin/sh
}

function install_exim4 {
	check_install mail exim4
	if [ -f /etc/exim4/update-exim4.conf.conf ]
	then
		sed -i \
			"s/dc_eximconfig_configtype='local'/dc_eximconfig_configtype='internet'/" \
			/etc/exim4/update-exim4.conf.conf
		invoke-rc.d exim4 restart
	fi
}

function install_dotdeb {
	#echo "deb http://mirror.us.leaseweb.net/dotdeb/ stable all" >> /etc/apt/sources.list
	#echo "deb-src http://mirror.us.leaseweb.net/dotdeb/ stable all" >> /etc/apt/sources.list
	echo "deb http://packages.dotdeb.org squeeze all" >> /etc/apt/sources.list
	echo "deb-src http://packages.dotdeb.org squeeze all" >> /etc/apt/sources.list
	wget -q -O - http://www.dotdeb.org/dotdeb.gpg | apt-key add -
}

function install_syslogd {
	# We just need a simple vanilla syslogd. Also there is no need to log to
	# so many files (waste of fd). Just dump them into
	# /var/log/(cron/mail/messages)
	check_install /usr/sbin/syslogd inetutils-syslogd
	invoke-rc.d inetutils-syslogd stop

	for file in /var/log/*.log /var/log/mail.* /var/log/debug /var/log/syslog
	do
		[ -f "$file" ] && rm -f "$file"
	done
	for dir in fsck news
	do
		[ -d "/var/log/$dir" ] && rm -rf "/var/log/$dir"
	done

	cat > /etc/syslog.conf <<END
*.*;mail.none;cron.none -/var/log/messages
cron.*				  -/var/log/cron
mail.*				  -/var/log/mail
END

	[ -d /etc/logrotate.d ] || mkdir -p /etc/logrotate.d
	cat > /etc/logrotate.d/inetutils-syslogd <<END
/var/log/cron
/var/log/mail
/var/log/messages {
	rotate 4
	weekly
	missingok
	notifempty
	compress
	sharedscripts
	postrotate
		/etc/init.d/inetutils-syslogd reload >/dev/null
	endscript
}
END

	invoke-rc.d inetutils-syslogd start
}

function install_mysql {
	# Install the MySQL packages
	check_install mysqld mysql-server
	check_install mysql mysql-client

	# Install a mid-end copy of the my.cnf to disable InnoDB, and then delete
	# all the related files.
	invoke-rc.d mysql stop
	rm -f /var/lib/mysql/ib*
	cat > /etc/mysql/conf.d/midendbox.cnf <<END
[mysqld]
default-storage-engine = MyISAM
key_buffer = 32M
query_cache_size = 128M
skip-innodb
END
	invoke-rc.d mysql start

	# Generating a new password for the root user.
	passwd=`get_password root@mysql`
	mysqladmin password "$passwd"
	cat > ~/.my.cnf <<END
[client]
user = root
password = $passwd
END
	chmod 600 ~/.my.cnf
}

function install_nginx {
	cpu=`cat /proc/cpuinfo | grep processor | wc -l`
	
	check_install nginx nginx
    
    # Need to increase the bucket size for Debian 5.
	cat > /etc/nginx/conf.d/midendbox.conf <<END
server_names_hash_bucket_size 64;
END
	if [ -f /etc/nginx/nginx.conf ]
	then
		mv /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak
	fi
	cat > /etc/nginx/nginx.conf <<EOF
user www-data;
worker_processes $cpu;
pid /var/run/nginx.pid;

events {
	worker_connections 2048;
	# multi_accept on;
}

http {
	## Basic Settings
	tcp_nopush on;
	tcp_nodelay on;
	types_hash_max_size 2048;
	client_max_body_size 20M;
	client_body_buffer_size 128k;

	include /etc/nginx/mime.types;

	access_log /var/log/nginx/access.log;
	error_log /var/log/nginx/error.log;

	## General Options  
	charset                 utf-8;
	default_type            application/octet-stream;
	ignore_invalid_headers  on;
	keepalive_timeout       65;
	keepalive_requests      20;
	max_ranges              0;
	#open_file_cache         max=1000 inactive=1h;
	#open_file_cache_errors  on;
	#open_file_cache_min_uses 3;
	#open_file_cache_valid   1m;
	recursive_error_pages   on;
	sendfile                on;
	server_tokens           off;
	source_charset          utf-8;

	## Log Format
	log_format  main  '\$remote_addr \$host \$remote_user [\$time_local] "\$request" \$status \$body_bytes_sent "\$http_referer" "\$http_user_agent" \$ssl_cipher \$request_time';

	## Compression
	gzip                 on;
	gzip_static          on;
	gzip_vary            on;
	gzip_disable "msie6";
	gzip_proxied any;
	gzip_comp_level 6;
	gzip_buffers 16 8k;
	gzip_http_version 1.1;
	gzip_types text/plain text/css application/json application/x-javascript text/xml application/xml application/xml+rss text/javascript;

	## Virtual Host Configs
	include /etc/nginx/conf.d/*.conf;
	include /etc/nginx/sites-enabled/*;
}

EOF
        
    invoke-rc.d nginx restart
}

function install_php {   
	check_install php5 php5 php5-cli php5-mysql php-apc php5-dev php5-mcrypt php5-imagick php5-common php5-suhosin php5-curl php5-intl php-gettext php-pear
	check_install php5-fpm php5-fpm
	pecl install rar
	pecl install zip

	mkdir -p /var/www
	chown www-data:www-data /var/www
	mkdir -p /var/lib/www
	chown www-data:www-data /var/lib/www

	update-rc.d php5-fpm defaults

	mv /etc/php5/conf.d/apc.ini /etc/php5/conf.d/orig.apc.ini

	cat > /etc/php5/conf.d/apc.ini <<END
[APC]
extension=apc.so
apc.enabled=1
apc.shm_segments=1
apc.shm_size=64
apc.ttl=7200
apc.user_ttl=7200
apc.num_files_hint=1024
apc.mmap_file_mask=/tmp/apc.XXXXXX
apc.max_file_size = 1M
apc.post_max_size = 1000M
apc.upload_max_filesize = 1000M
apc.enable_cli=0
apc.rfc1867=0
apc.include_once_override = 0
apc.canonicalize = 0
apc.stat = 0
END

	mv /etc/php5/conf.d/suhosin.ini /etc/php5/conf.d/orig.suhosin.ini

	cat > /etc/php5/conf.d/suhosin.ini <<END
; configuration for php suhosin module
extension=suhosin.so
suhosin.executor.include.whitelist="phar"
suhosin.request.max_vars = 2048
suhosin.post.max_vars = 2048
suhosin.request.max_array_index_length = 256
suhosin.post.max_array_index_length = 256
suhosin.request.max_totalname_length = 8192
suhosin.post.max_totalname_length = 8192
suhosin.sql.bailout_on_error = Off
END

	cat > /etc/php5/conf.d/rar.ini <<END
; configuration for php rar module
extension=rar.so
END

cat > /etc/php5/conf.d/zip.ini <<END
; configuration for php zip module
extension=zip.so
END

	if [ -f /etc/php5/fpm/php.ini ]
		then
			sed -i \
				"s/upload_max_filesize = 2M/upload_max_filesize = 200M/" \
				/etc/php5/fpm/php.ini
			sed -i \
				"s/post_max_size = 8M/post_max_size = 200M/" \
				/etc/php5/fpm/php.ini			
	fi
    
    invoke-rc.d php5-fpm restart
}

function install_site {
	if [ -z "$1" ] || [ -z "$2" ]
	then
		die "Usage: `basename $0` site <hostname> <your name>"
	fi

	mkdir -p /var/www/$1/{public_html,logs}
	chown root:root -R "/var/www/$1"

	cat > "/var/www/$1/public_html/index.php" <<END
<?php
/*
[MySQL]
database: database_name_here
username: username_here
password: password_here
*/
echo "Hello, $2.";
?>
END
    cat > "/var/www/$1/public_html/pinfo.php" <<END
<?php
  phpinfo();
?>    
END

	# Setting up the MySQL database
	dbname=`echo $1 | tr . _`
	userid=`get_domain_name $1`
	# MySQL userid cannot be more than 15 characters long
	userid="${userid:0:15}"
	passwd=`get_password "$userid@mysql"`

	sed -i "s/database_name_here/$dbname/; s/username_here/$userid/; s/password_here/$passwd/" \
		"/var/www/$1/public_html/index.php"
	mysqladmin create "$dbname"
	echo "GRANT ALL PRIVILEGES ON \`$dbname\`.* TO \`$userid\`@\`localhost\` IDENTIFIED BY '$passwd';" | \
		mysql
		
	# Setting up php5-fpm config
	# http://www.howtoforge.com/php-fpm-nginx-security-in-shared-hosting-environments-debian-ubuntu
	cat > "/etc/php5/fpm/pool.d/$1.conf" <<EOF
[$1]

listen = /var/www/$1/listen.sock

user = www-data
group = www-data

; Recommended by http://www.webhostingtalk.com/showthread.php?t=1025286
pm = dynamic
pm.max_children = 35
pm.start_servers = 4
pm.min_spare_servers = 2
pm.max_spare_servers = 10 
pm.max_requests = 500
request_terminate_timeout = 30s
chdir = /    
EOF
	if [ -f /etc/php5/fpm/pool.d/www.conf ]
	then
		mv /etc/php5/fpm/pool.d/www.conf /etc/php5/fpm/pool.d/www.conf.bak
	fi
	# Setting up Nginx mapping
	cat > "/etc/nginx/sites-available/$1.conf" <<END
server {
	server_name $1 www.$1;
	root /var/www/$1/public_html;
	access_log /var/www/$1/logs/access.log;
	error_log /var/www/$1/logs/error.log;    

	index index.php;

	location / {
		autoindex on;
		try_files \$uri \$uri/ @fuel;
	}

	location @fuel {
		rewrite ^(.*) /index.php?\$1 last;
	}

	location ~ ^(?<script>.+\.php)(?<path_info>.*)$ {
		# Zero-day exploit defense.
		# http://forum.nginx.org/read.php?2,88845,page=3
		# Won't work properly (404 error) if the file is not stored on this server, which is entirely possible with php-fpm/php-fcgi.
		# Comment the 'try_files' line out if you set up php-fpm/php-fcgi on another machine.  And then cross your fingers that you won't get hacked.

		fastcgi_split_path_info ^(.+\.php)(/.+)$;
		include /etc/nginx/fastcgi_params;

		# Some default config
		fastcgi_connect_timeout        60;
		fastcgi_send_timeout          180;
		fastcgi_read_timeout          180;
		fastcgi_buffer_size          128k;
		fastcgi_buffers            4 256k;
		fastcgi_busy_buffers_size    256k;
		fastcgi_temp_file_write_size 256k;

		fastcgi_intercept_errors    on;
		fastcgi_ignore_client_abort off;

		fastcgi_index index.php;
		fastcgi_param SCRIPT_FILENAME \$document_root\$script;
		if (-f \$request_filename) {
			fastcgi_pass unix:/var/www/$1/listen.sock;
		}
	}

	location /favicon.ico {
		log_not_found off;
		access_log off;
	}

	location /robots.txt {
		allow all;
		log_not_found off;
		access_log off;
	}

	location ~ /\. { 
		deny all; 
		access_log off; 
		log_not_found off; 
	}

	# This matters if you use drush
	location /backup {
		deny all;
	}

	# Very rarely should these ever be accessed outside of your lan
	location ~* \.(txt|log)$ {
		allow 192.168.0.0/16;
		deny all;
	}

	location ~* \.(js|css|png|jpg|jpeg|gif|ico)$ {
		expires max;
		add_header Cache-Control public;    
		log_not_found off;
	}
}

END
	ln -s /etc/nginx/sites-available/$1.conf /etc/nginx/sites-enabled/$1.conf
	invoke-rc.d php5-fpm restart
	invoke-rc.d nginx restart
}

function install_iptables {

	check_install iptables

	# Create startup rules
	cat > /etc/iptables.up.rules <<END
*filter

# http://articles.slicehost.com/2010/4/30/ubuntu-lucid-setup-part-1

#  Allows all loopback (lo0) traffic and drop all traffic to 127/8 that doesn't use lo0
-A INPUT -i lo -j ACCEPT
-A INPUT ! -i lo -d 127.0.0.0/8 -j REJECT

#  Accepts all established inbound connections
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

#  Allows all outbound traffic
#  You can modify this to only allow certain traffic
-A OUTPUT -j ACCEPT

# Allows HTTP and HTTPS connections from anywhere (the normal ports for websites)
-A INPUT -p tcp --dport 80 -j ACCEPT	
-A INPUT -p tcp --dport 443 -j ACCEPT

# UN-COMMENT THESE IF YOU USE INCOMING MAIL!

# Allows POP (and SSL-POP)
#-A INPUT -p tcp --dport 110 -j ACCEPT
#-A INPUT -p tcp --dport 995 -j ACCEPT

# SMTP (and SSMTP)
#-A INPUT -p tcp --dport 25 -j ACCEPT
#-A INPUT -p tcp --dport 465 -j ACCEPT

# IMAP (and IMAPS)
#-A INPUT -p tcp --dport 143 -j ACCEPT
#-A INPUT -p tcp --dport 993 -j ACCEPT

#  Allows SSH connections (only 3 attempts by an IP every minute, drop the rest to prevent SSH attacks)
-A INPUT -p tcp -m tcp --dport $1 -m state --state NEW -m recent --set --name DEFAULT --rsource
-A INPUT -p tcp -m tcp --dport $1 -m state --state NEW -m recent --update --seconds 60 --hitcount 3 --name DEFAULT --rsource -j DROP
-A INPUT -p tcp -m state --state NEW --dport $1 -j ACCEPT

# Allow ping
-A INPUT -p icmp -m icmp --icmp-type 8 -j ACCEPT

# log iptables denied calls (Can grow log files fast!)
#-A INPUT -m limit --limit 5/min -j LOG --log-prefix "iptables denied: " --log-level 7

# Reject all other inbound - default deny unless explicitly allowed policy
#-A INPUT -j REJECT
#-A FORWARD -j REJECT

# It's safer to just DROP the packet
-A INPUT -j DROP
-A FORWARD -j DROP

COMMIT
END

	# Set these rules to load on startup
	cat > /etc/network/if-pre-up.d/iptables <<END
#!/bin/sh
/sbin/iptables-restore < /etc/iptables.up.rules
END

	# Make it executable
	chmod +x /etc/network/if-pre-up.d/iptables

	# Load the rules
	iptables-restore < /etc/iptables.up.rules

	# You can flush the current rules with /sbin/iptables -F
	echo 'Created /etc/iptables.up.rules and startup script /etc/network/if-pre-up.d/iptables'
	echo 'If you make changes you can restore the rules with';
	echo '/sbin/iptables -F'
	echo 'iptables-restore < /etc/iptables.up.rules'
	echo ' '
}

function remove_unneeded {
	# Some Debian have portmap installed. We don't need that.
	check_remove /sbin/portmap portmap

	# Remove rsyslogd, which allocates ~30MB privvmpages on an OpenVZ system,
	# which might make some low-end VPS inoperatable. We will do this even
	# before running apt-get update.
	check_remove /usr/sbin/rsyslogd rsyslog

	# Other packages that seem to be pretty common in standard OpenVZ
	# templates.
	check_remove /usr/sbin/apache2 'apache2*'
	check_remove /usr/sbin/named bind9
	check_remove /usr/sbin/smbd 'samba*'
	check_remove /usr/sbin/nscd nscd

	# Need to stop sendmail as removing the package does not seem to stop it.
	if [ -f /usr/lib/sm.bin/smtpd ]
	then
		invoke-rc.d sendmail stop
		check_remove /usr/lib/sm.bin/smtpd 'sendmail*'
	fi
    
	check_install wget wget    
	cat >> /etc/apt/sources.list <<END
deb http://packages.dotdeb.org stable all
END
	wget http://www.dotdeb.org/dotdeb.gpg
	cat dotdeb.gpg | sudo apt-key add -
	rm dotdeb.gpg    
    
}

function update_upgrade {
	# Run through the apt-get update/upgrade first. This should be done before
	# we try to install any package
	apt-get -q -y update
	apt-get -q -y upgrade
}

function update_timezone {
	dpkg-reconfigure tzdata
}

function secure {
	if [ -z "$1" ] || [ -z "$2" ]
	then
		die "Usage: `basename $0` secure [ssh-port-# username]"
	fi
		
	install_iptables $1
	
	adduser $2
	
    if [ -f /etc/ssh/sshd_config ]
    then
        sed -i \
            "s/Port 22/Port $1/" \
            /etc/ssh/sshd_config
        sed -i \
            "s/PermitRootLogin yes/PermitRootLogin no/" \
            /etc/ssh/sshd_config
			
        invoke-rc.d ssh restart
    fi
}

########################################################################
# START OF PROGRAM
########################################################################
export PATH=/bin:/usr/bin:/sbin:/usr/sbin

check_sanity
case "$1" in
mysql)
	install_mysql
	;;
nginx)
	install_nginx $2
	;;
php)
	install_php
	;;
system)
	install_dotdeb
	update_timezone
	remove_unneeded
	update_upgrade
	update-grub 0	
	install_exim4
	install_dash
	install_vim
	install_nano
	install_htop
	install_mc
	install_iotop
	install_iftop
	install_syslogd
    check_install make g++
	;;
site)
	install_site $2 $3
	;;
secure)
	secure $2 $3
	;;
*)
	echo 'Usage:' `basename $0` '[option] [argument]'
	echo 'Available options (in recomended order):'
	echo '  - system                 (remove unneeded, upgrade system, install base software)'
	echo '  - mysql                  (install MySQL and set root password)'
	echo '  - nginx                  (install nginx and create sample PHP vhosts)'
	echo '  - php                    (install PHP5-FPM with APC, cURL, suhosin, etc...)'
	echo '  - site      [domain.tld] (create nginx vhost and /var/www/$site/public)'
	echo '  - secure	[port, user] (setup basic firewall with HTTP open, disables ssh root login and creates a new user)'
	echo '  '
	;;
esac


