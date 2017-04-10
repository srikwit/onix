#!/bin/bash
#
#  Obtain performance and forensics information of Linux/UNIX systems

############################################################################
#  References:
#  1. Linux Forensics for Non-Linux folks - Deer Run Associates
#  2. UNIX Investigation training - Fireeye
#  3. Digital forensics for UNIX - SANS
#  4. UNIX/Linux forensics - Lamar University
#  5. UNIX Forensic analysis basics - University of Washington
#  6. UNIX privesc check library
#
#  TODO:
#  1. Tiger source
#  2. LSAT modules
#  3. Auscert.org.au/5816 
############################################################################

############################################################################
#  Style guide:
#  1. Google shell style guide
############################################################################

############################################################################
#  Contents to fetch
#  1. Directories to examine and their permissions:
#  2. System Profiling
#    Distribution name and version
#    Computer name
#    IP addresses
#    Installation date
#    Network configuration - Static or DHCP
#    /etc/inetd.conf, /etc/xinetd.conf, /etc/xinetd.d
#    Nameserver used
#    Timezone, system time, NTP configuration
#  3. User accounts
#  4. User Login history
#  5. Web Artifacts
#  6. File browser history (TODO)
#    Thumbnails and recent files
#  7. Command history
#  6. Web Artifacts
#  8. SSH
#  9. Services
#    /etc/inittab, /etc/init.d/, /etc/rc.d, /etc/init.conf, /etc/init
#  10. Scheduled tasks
#    /etc/cron*
#    /var/spool/cron/*
#    Permissions on scheduled tasks
#  11. Process tree and permissions of the binary path
#  12. Network statistics and traffic
#  13. Kernel configuration
#  14. Disk statistics
#  15. Printer usage
#  16. NFS mounts and permissions
#  17. Examine environment variables
#  18. Check SELinux support
#  19. List of open files
############################################################################

display_banner() {
echo "MMMMMMMMMMMMMMMNNMMMMMMMMMMMMMMMMMMMMMMMMMMMNddossssssssyNMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM"
echo "MMMMMMMMMMMMMM/++mMMMMMMMMMMMMMMMMMMMMy+:------:+--+/::/+-+dmhs+/ydMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM"
echo "MMMMMMMMMMMMMM+-|dMMMMMMMMMMMMMMMMMMMs/--::|--|/|----------+s+:::::ohdNMMMMMMMmmmNNMMMMMMMMMMMMMMMMM"
echo "MMMMMMMMMMMMMM/++yMMMMMMMMMMMMMMMMMMs/+::::|--|:+------------+oso+/+o+oNMNNho////+oydNMMMMMMMMMMMMMM"
echo "MMMMMMMMMMMMMN/o/oMMMMMMMMMNdyyyhhhy++so+/:|---:s+-------+/////+h+--+oydsoo+ooooooooooyhmNMMMMMMMMMM"
echo "MMMMMMMMMMMMMm/o//NMMMMMNh+:-..--::::::::/+--+osyyyo+---+///////y|--|hyyhooo+--+so+-+o++oosNMMMMMMMM"
echo "MMMMMMMMMMMMMd++//dMMNho:-......----:::::::::ohyyyyyyso+////++//y|--|syydoo+----+so+-+oooooyNMMMMMMM"
echo "MMMMMMMMMMMMMh|///hMNo:---------:------:::::/o/shyyyyyhy///+hy++h+---+hyhy+-|oo|-+sooooooos+hMMMMMMM"
echo "MMMMMMMMMMMMMh++//sMo:o:---:::::::::----:-:+////yhyyyyyho//yyyhhdo+-+syyhyo|-----|osoooooos++NMMMMMM"
echo "MMMMMMMMMMMMMyo+-+oh::/+/:::::::::::::::/+--+////syyyyyyyssyyyhdhyyyyyyyds+-------+oysoooos++hMMMMMM"
echo "MMMMMMMMMMMMMoo|-|os::/+oo+-+//+-+/+--+o+------+osdyyyyyssssshhyyyyyyyhhhy+------+oosooooooo+oNMMMMM"
echo "MMMMMMMMMMMMM+---+/o+ooooo+---+s|////oo+--------+ddyyysooooshhyyyyyyydhhhhyo+--+ooooooooooooosmMMMMM"
echo "MMMMMMMMMMMMN/||o|/+y+//++sso+----+///+///////++yydyysooosydhyysyyyhhhyyyhhhysoooooooooo+osyhmMMMMMM"
echo "MMMMMMMMMmhos:||s+--+s/////+ooo+-+oooo/////////oyydyysshdmMMNmdmNyssyyyyyyyyhhhyyysoso+ooyhhmMMMMMMM"
echo "MMMMMMMMh/-:o:++s+-+oo///////+soo+///////////oyyssmNNNMMMMMMMMMMMdsoosssyyyyyyyyyyyhhyoyyhhhdNMMMMMM"
echo "MMMMMMmo::::o:o+s|oo+///++///s/+so+////////+sysooyNMMMMMMMMMMMMMMMNdsooossssssyyyyyyyhhyyhdhyhdNMMMM"
echo "MMMMMh/:::-//:sos++/////o///++///ossoo+-+osysssymMMMMMMMMMMMMMMMMMMMMdsssyssssssyyyyyyyyhhyyyyyhMMMM"
echo "MMMMm/o:::++/:so////////o+/++//////oyyyyyyyysymMMMMMMMMMMMMMMMMMMMMMMMMMNNmyyyyyyyhhhhhhhhyyyyyymMMM"
echo "MMMMs/+::-+:o++//////////+o|////////+dyyhyysyNMMMMMMMMMMMMMMMMMMMMMMMMMMMMhossyhhhhdhhhhhhyyyyyyhMMM"
echo "MMMd::/:::--://///////////s+/////////hyyyyhmMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMmyyyyyyyyhhhhhhhhhyyyhNMMM"
echo "MMMy:/:--:::-:////////////ss/////////mmNNMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMdyyyyyyyyyhhhdhhhhhymMMMM"
echo "MMMMy+:|::+::///////////oo+o////////+MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMhssyyyyyyyyhddhhhymMMMMM"
echo "MMMd++:+/+:-:+/://+o+/::s+/+s+//////hMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMmhysyyyyyyhhhhyymMMMMMM"
echo "MMMy:/-./o.--:ss+/|:``.++///+o+-+//ohMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMNhsyhyhhdddhhdNMMMMMM"
echo "MMMm/-:://..-/s+ss+/:/+::/o+---+oooodMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMo+-+ssyydhhhhhhhNMMMMM"
echo "MMMN/:----.../+oo/:-----:/o+oossosdNMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMy+/osooooydhhhhhhhdNMMM"
echo "MMMh::::o...--+/::----::++shhysdMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMddh+ssoosoooooyyhhhhhhdMMM"
echo "MMMs::::o...:|/::::+-:++sdNyyymMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMdsoho+osoysooooooosdhhhhNMMM"
echo "MMMy/:::o..--+:::::|:oosNNhydNMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMmsooohhoooosoooooooydhhhhmMMMM"
echo "MMMMdo::o.-/o/::::/+ssymNdyyNMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMdysssssyyoooydhyyyhhhhhyyhNMMMM"
echo "MMMMMMdos::osooso+oyhdmdysymMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMNmyyyyhsssssssyyshhhhhhhyyyyyymMMMMMM"
echo "MMMMMMMMdyoosdNNNdhhhyssydNMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMNhssooshyssssssysydhhhyyyyyysydNMMMMMMM"
echo "MMMMMMMMMMNmsossyyyysydNMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMyoosssshyyyyssshyyhhhhhhddmmmNMMMMMMMMM"
echo "MMMMMMMMMMMMNmmmmmddmMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMmdddmooosyssshdhhhhhhyyyyyyyhMMMMMMMMMMMMMMM"
echo "MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMhooooyossssssssyddhhhyyyyyyhhmMMMMMMMMMMMMMMM"
echo "MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMNsoooosdysssssyyyhhhdddmmdmNNMMMMMMMMMMMMMMMMMM"
echo "MMMMM+--------------------------------+MMMMMMMMMMMMMMdso+osyyddhyyyyhhyyyyyyNMMMMMMMMMMMMMMMMMMMMMMM"
echo "MMMMM|MMXMMM  M    M  MMMMMMM MM     M|MMMMMMMMMMMMMMhssssssyhhddhhhhyyyyyydMMMMMMMMMMMMMMMMMMMMMMMM"
echo "MMMMM|M    M  MM   M    MMM    MM M MM|MMMMMMMMMMMMmhhsssssshhhhhddhhmmmmmNMMMMMMMMMMMMMMMMMMMMMMMMM"
echo "MMMMM|X    M  M MM M    MMM     MM MM |MMMMMMMMMMMyo+hdhyhhhhhhyyyyhdMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM"
echo "MMMMM|M    M  M   MM    MMM    MM   MM|MMMMMMMMMMhooooyhdhhhhyyyyydNMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM"
echo "MMMMM|MMMMMM  M    M  MMMMMMM MMM    M|MMMMMMMMMyossssssyddhhhhddNMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM"
echo "MMMMM+--------------------------------+MMMMMMMMMyssyysyyhhhhhhdMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM"
echo "MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMdyyhhyyyhhhhhhNMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM"
echo "MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMNdyyyyyhhhhhmMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM"
echo "MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMmdhhhhhhyyMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM"
echo "MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMmhhhhdyyNNhhhhhdNMMmhhmMMMMMMMMMMMMMMMMMMMMM"
echo "MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMNNddhhddysssssydmhyhhNMMMMMMMMMMMMMMMMMMMM"
echo "MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMNmNNdhhhyyyyydhhhdNMMMMMMMMMMMMMMMMMMMM"
echo "MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMNmddhhhdNMNNMMMMMMMMMMMMMMMMMMMMMM"
}

examine_critical_directories() {
############################################################################
#  Directories to examine and their permissions:
#    /etc - system configuration
#    /var/log - Application logs
#    /home/$USER - User data and user configuration
#    /tmp - tmp directory 
############################################################################
echo "[+] Fetching contents from critical directories"
find /etc -type f -exec ls -lahs '{}' \; 2> etc_system_files_configuration_error 1> etc_system_files_configuration_data
find /etc -type d -exec ls -lahsd '{}' \; 2> etc_system_directory_configuration_error 1> etc_system_directory_configuration_data
find /var/log -type f -exec ls -lahs '{}' \; 2> var_log_files_configuration_error 1> var_log_files_configuration_data
find /var/log -type d -exec ls -lahsd '{}' \; 2> var_log_directory_configuration_error 1> var_log_directory_configuration_data
find /home -type f -exec ls -lahs '{}' \; 2> home_directory_files_configuration_error 1> home_directory_files_configuration_data
find /home -type d -exec ls -lahsd '{}' \; 2> home_directory_configuration_error 1> home_directory_configuration_data
find /tmp -type f -exec ls -lahs '{}' \; 2> tmp_files_configuration_error 1> tmp_files_configuration_data
find /tmp -type d -exec ls -lahsd '{}' \; 2> tmp_directory_configuration_error 1> tmp_directory_configuration_data
}

examine_user_accounts() {
############################################################################
#  User accounts
#    /etc/passwd
#    /etc/shadow
#    /etc/sudoers
#    /etc/group
############################################################################
echo "[+] Fetching user account information"
cat /etc/passwd 2> passwd_error 1> passwd_data
cat /etc/shadow 2> shadow_error 1> shadow_data
cat /etc/group 2> group_error 1> group_data
cat /etc/sudoers 2> sudoers_error 1> sudoers_data
}

examine_user_login() {
############################################################################
#  User Login history
#    /var/log/wtmp or last command <---Last logon
#    /var/log/auth.log
#    /var/log/secure
#    /var/log/audit/audit.log
#    /var/log/utmp or w or who <--Current logon
#    /var/log/lastlog <--Logon times and sources
#    /var/log/btmp <--Failed login history
#    /var/log/messages <--syslog messages
#    lastlog command
############################################################################
echo "[+] Fetching details of user logins"
last iwF 2> last_good_logins_error 1> last_good_logins_data
lastb iwF 2> last_bad_logins_error 1> last_bad_logins_data
w -hi 2> current_logged_in_user_bad 1> current_logged_in_user_data
cp /var/log/messages syslog_messages_data 2> syslog_messages_bad
}

examine_web_artifacts() {
############################################################################
#  Web Artifacts
#    Firefox: $HOME/.mozilla/firefox/*.default
#    Chromium: $HOME/.config/chromium/Default
############################################################################
echo "[+] Fetching web artifacts"
cp -R $HOME/.mozilla/firefox/ . 2> firefox_error
cp -R $HOME/.config/chromium/ . 2> chromium_error
}

examine_suid_and_sgid() {
echo "[+] Fetching suid and sgid files"
find / -perm /4000 -type f -exec ls -lahs '{}' \; 2> suid_error 1> suid_data
find / -perm /2000 -type f -exec ls -lahs '{}' \; 2> sgid_error 1> sgid_data
find / -perm /6000 -type f -exec ls -lahs '{}' \; 2> sgid_and_suid_error 1> sgid_and_suid_data
}

examine_kernel_parameters() {
sysctl -a 2> kernel_parameters_bad 1> kernel_parameters_data
}

examine_shell_history() {
############################################################################
#  Command history
#    $HOME/.bash_history
#    /var/log/auth.log
#    /var/log/sudo.log
#    .sh_history
############################################################################
echo "[+] Fetching shell history"
cp $HOME/.bash_history bash_history_data 2> bash_history_error
cp /var/log/auth.log var_log_auth_log_data 2> var_log_auth_log_error
}

examine_ssh_details() {
############################################################################
#  SSH
#    $HOME/.ssh
#      1. known_hosts - hosts connected to from here
#      2. authorized_keys - public keys used for logins to here
#      3. id_rsa - private keys used to login elsewhere
############################################################################
echo "[+] Fetching SSH details"
cp -R $HOME/.ssh/ ssh 2> ssh_error
}

examine_selinux_settings() {
echo "[+] Fetching SELinux status"
sestatus -v 2> selinux_error 1> selinux_data
}

examine_environment_variables() {
echo "[+] Fetching environment variables"
env 2> env_error 1> env_data
}

examine_running_processes() {
echo "[+] Fetching running processes"
pstree -apgnu 2> process_tree_error 1> process_tree_data
ps -efjlMH --forest 2> ps_error 1> ps_data
}

examine_disk_usage() {
echo "[+] Fetching disk status"
df -ahT --total 2> disk_usage_error 1> disk_usage_data
}

examine_mounted_filesystems() {
echo "[+] Fetching filesystem mount information"
cat /proc/mounts 1> proc_mounts_data 2> proc_mounts_error
cat /etc/mtab 1> etc_mtab_data 2> etc_mtab_error
}

examine_connected_printers() {
echo "[+] Fetching printer data"
lpstat -t 1> printer_data 2> printer_error
}

examine_scheduled_tasks() {
echo "[+] Fetching scheduled tasks"
for user in $(cut -f1 -d: /etc/passwd);
do
  echo $user 1>> cron_data;
  echo $user 1>> cron_bad;
  crontab -u $user -l 2>> cron_bad >> cron_data ;
done

cat /etc/crontab 2> system_wide_crontab_error 1> system_wide_crontab_data

find /etc/cron* -type f -exec echo {} >> cron_data \; -exec cat {} >> cron_data \; -exec echo $'\n' >> cron_data \;
}

examine_services() {
echo "[+] Fetching services"
systemctl list-units -al >> systemctl_list_units_data 2>> systemctl_list_units_error
systemctl list-sockets -al >> systemctl_list_sockets_data 2>> systemctl_list_sockets_error
systemctl list-timers -al >> systemctl_list_timers_data 2>> systemctl_list_timers_error
systemctl list-unit-files -al >> systemctl_list_unit_files_data 2>> systemctl_list_unit_files_error
systemctl list-dependencies -al >> systemctl_list_dependencies_data 2>> systemctl_list_dependencies_error
service --status-all >> service_status_data 2>> service_status_error
}

examine_network_connections() {
echo "[+] Fetching network information"
netstat -s 2> network_statistics_error > network_statistics_data
netstat -nr 2> kernel_routing_table_error > kernel_routing_table_data
netstat -aepW 2> netstat_error > netstat_data
}

examine_system_information() {
echo "[+] Fetching system details"
lsb_release -a 2> distribution_error 1> distribution_data
uname -a 2> system_information_error 1> system_information_data
ifconfig -a 2> ip_address_error 1> ip_address_data
cat /etc/hosts 2> local_dns_resolution_error 1> local_dns_resolution_data
cat /etc/resolv.conf  2> remote_dns_server_error 1> remote_dns_server_data
cat /var/lib/dhcp/dhclient.leases 2> dhcp_error 1> dhcp_data
date 2> system_date_error 1> system_date_data
cat /etc/ntp.conf 2> ntp_configuration_error 1> ntp_configuration_data
cat /etc/inetd.conf 2> inetd_configuration_error 1> inetd_configuration_data
}

examine_open_files() {
echo "[+] Fetching open files"
lsof 2> list_of_open_files_error 1> list_of_open_files_data
}

examine_package_manager() {
echo "[+] Fetching package manager details"
dpkg --verify 2> dpkg_verify_error 1> dpkg_verify_data
dpkg --audit 2> dpkg_audit_error 1> dpkg_audit_data
dpkg --get-selections 2> dpkg_get_selections_error 1> dpkg_get_selections_data
dpkg --print-architecture 2> dpkg_default_architecture_error 1> dpkg_default_architecture_data
dpkg --print-foreign-architectures 2> dpkg_foreign_architecture_error 1> dpkg_foreign_architecture_data
}

examine_active_data() {
echo "[!] Obtaining active data"
examine_user_login
examine_running_processes
examine_network_connections
examine_connected_printers
examine_services
examine_open_files
echo "[!] Finished obtaining active data"
echo ""
}

examine_passive_data() {
echo "[!] Obtaining passive data"
examine_system_information
examine_critical_directories
examine_user_accounts
examine_web_artifacts
examine_suid_and_sgid
examine_kernel_parameters
examine_shell_history
examine_ssh_details
examine_selinux_settings
examine_environment_variables
examine_disk_usage
examine_mounted_filesystems
examine_scheduled_tasks
examine_package_manager
#examine_kernel_modules [TODO]
echo "[!] Finished obtaining passive data"
echo ""
}

display_exit_status() {
echo "[+] Success!"
echo ""
}

display_exit_message() {
clear
}

mkdir Evidence 2> /dev/null
cd Evidence
clear
display_banner
sleep 5
clear
examine_active_data
examine_passive_data
display_exit_success
cd ..
