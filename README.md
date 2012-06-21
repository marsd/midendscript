## Mid End Script for Mid End Boxes (Debian 6)

Modified script to run optimally on 1-2GB RAM VPS

- Removed dropbear
- Added secure to create a new ssh user, change ssh port and disable ssh root logins
- Moved install_iptables into secure
- Base software list: make g++ iptables dash syslogd exim4 vim nano mc htop iftop iotop
- MySQL (v5.1+ W/O Innodb, configured for mid-end VPS with query caching)
- PHP-FPM (v5.3+ with APC installed and configured) 
Other packages installed:
 php5-cli php5-mysql php-apc php5-dev php5-mcrypt php5-imagick php5-common php5-suhosin php5-curl php5-intl php-gettext php-pear    
 PECL packages: rar zip
 PECL extensions are added as additional inis in /etc/php/conf.d
- Install Site 
Creates a DOMAIN.conf in /etc/php5/fpm/pool.d/
Creates a DOMAIN.conf in /etc/nginx/sites-available/
Attempts to fix image file script execution exploits
Attempts to rewrite /index.php? params (currently for FuelPHP, can be modified for other frameworks)		
Creates the following directories and files:
/var/www/DOMAIN/
/var/www/DOMAIN/public_html
index.php (MySQL database, username and password are in comments)
pinfo.php (phpinfo)
/var/www/DOMAIN/logs
	
	
## Usage:
	$ wget --no-check-certificate https://raw.github.com/Xeoncross/lowendscript/master/setup-debian.sh
	$ chmod 744 setup-debian.sh
	$ ./setup-debian.sh system
	$ ./setup-debian.sh mysql
	$ ./setup-debian.sh nginx
	$ ./setup-debian.sh php
	$ ./setup-debian.sh site example.com <MySQL username per site>
	$ ./setup-debian.sh secure 12345 user3412
	
## After installation
- Disconnect from your current SSH connection and reconnect using the new port and username.
- Use "su" to switch to root user after logging in
- MySQL root is given a new password which is located in ~root/.my.cnf.
- MySQL user for each site is located in "/var/www/<DOMAIN>/public_html/index.php" file, and should be removed after storing the password in a safe location.
- Delete, move or password protect "/var/www/<DOMAIN>/public_html/pinfo.php" file, which installed automatically on each new site installation.


## Credits

[LowEndBox admin (LEA)](https://github.com/lowendbox/lowendscript),
[Xeoncross](https://github.com/Xeoncross/lowendscript),
