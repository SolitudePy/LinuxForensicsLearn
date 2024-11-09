# Linux Artifacts

## System Configuration

### `/etc/passwd`
- **Type**: File
- **Description**: Contains user account information, including username, user ID, group ID, home directory, and default shell.
- **Forensic Use**: Identifies users on the system, their home directories, and account details, which can reveal suspicious accounts or unauthorized access.

### `/etc/shadow`
- **Type**: File
- **Description**: Stores password hashes for users in a restricted format.
- **Forensic Use**: Analyzing password hashes helps verify password strength and detect weak passwords or unauthorized accounts.

### `/etc/group`
- **Type**: File
- **Description**: Lists all user groups and their members.
- **Forensic Use**: Helps understand user permissions and roles, which is valuable for analyzing privilege escalation.

### `/etc/hosts`
- **Type**: File
- **Description**: Maps IP addresses to hostnames, overriding DNS.
- **Forensic Use**: Reveals DNS redirection attempts or local overrides, indicating potential dns poisoning.

### `/etc/hosts.allow` and `/etc/hosts.deny`
- **Type**: Files
- **Description**: Configures which hosts are allowed or denied access.
- **Forensic Use**: Can reveal unauthorized or unusual access control modifications.

### `/etc/resolv.conf`
- **Type**: File
- **Description**: Contains DNS server information.
- **Forensic Use**: Indicates DNS configuration changes or unauthorized servers.

### `/etc/login.defs`
- **Type**: File
- **Description**: Configures password expiration, login retries, and other user policies.
- **Forensic Use**: Detects security configurations around login policies.

### `/etc/ssh/sshd_config`
- **Type**: File
- **Description**: Configures SSH server settings.
- **Forensic Use**: Shows SSH configurations, which can indicate changes in remote access policies.

### `/etc/sudoers` and `/etc/sudoers.d/`
- **Type**: Files
- **Description**: Configures permissions for users to execute commands as superuser.
- **Forensic Use**: Detects unauthorized or overly permissive sudo configurations.

### `/etc/pam.d/`
- **Type**: Directory
- **Description**: Contains Pluggable Authentication Modules (PAM) configuration.
- **Forensic Use**: Examines authentication policies and can reveal any modified policies.

### `/etc/sysctl.conf`
- **Type**: File
- **Description**: Configures kernel parameters at runtime.
- **Forensic Use**: Indicates changes in system performance or security settings.

### `/etc/rsyslog.conf`
- **Type**: File
- **Description**: Configures log management and centralized logging.
- **Forensic Use**: Indicates log forwarding settings, which may affect log integrity.

### `/etc/environment`
- **Type**: File
- **Description**: Sets environment variables for system-wide use.
- **Forensic Use**: May reveal custom or malicious environment settings.

### `/etc/profile`
- **Type**: File
- **Description**: System-wide shell settings for all users.
- **Forensic Use**: Detects system-wide environment configurations.

### `/etc/bashrc` and `/etc/profile.d/`
- **Type**: Files
- **Description**: System-wide bash configuration.
- **Forensic Use**: Analyzes modifications in bash configuration for malicious changes.

### `/etc/motd`
- **Type**: File
- **Description**: Message of the day displayed on user login.
- **Forensic Use**: Can be used to communicate unauthorized or suspicious messages to users.

### `/etc/ntp.conf`
- **Type**: File
- **Description**: Configures Network Time Protocol settings.
- **Forensic Use**: Shows time synchronization settings, which may affect timestamp accuracy in logs.

### `/etc/audit/` and `/etc/audisp/`
- **Type**: Directories
- **Description**: Configures Linux audit framework and audit dispatcher.
- **Forensic Use**: Examines audit rules and event forwarding, useful for tracking system activities.

### `/etc/selinux/config`
- **Type**: File
- **Description**: Configures SELinux policies.
- **Forensic Use**: Reveals SELinux enforcement status, affecting system security policies.

### `/etc/rc.local`
- **Type**: File
- **Description**: Contains commands executed at system startup.
- **Forensic Use**: Common persistence mechanism for running custom scripts on boot.

### `/etc/issue`
- **Type**: File
- **Description**: Contains pre-login message for users.
- **Forensic Use**: May be altered to communicate unauthorized messages.

### `/etc/anacrontab`
- **Type**: File
- **Description**: Configures cron jobs that run on reboot or system start if a scheduled job was missed.
- **Forensic Use**: Reveals scheduled tasks that run on boot, useful for identifying persistence.

### `/etc/inittab`
- **Type**: File
- **Description**: Configures system startup and runlevels.
- **Forensic Use**: Defines system initialization, potentially altered for malicious persistence.

### `/etc/modprobe.d/`
- **Type**: Directory
- **Description**: Configures loadable kernel modules.
- **Forensic Use**: Checks for unauthorized kernel module loading or blacklisting.

### `/etc/grub2.cfg`
- **Type**: File
- **Description**: GRUB bootloader configuration.
- **Forensic Use**: Identifies boot settings, which may reveal modified boot configurations.

### `/etc/ld.so.conf` and `/etc/ld.so.conf.d'
- **Type**: Files
- **Description**: Configures shared library paths.
- **Forensic Use**: Examines library loading paths, which can be used for injecting malicious libraries.

### `/usr/lib/systemd/system/`
- **Type**: Directory
- **Description**: Contains systemd unit files that define services, targets, and other units managed by the systemd init system. These files are typically provided by installed packages.
- **Forensic Use**: Useful for identifying persistent services or examining unit files to detect unauthorized services or modifications to legitimate services.

### `/etc/systemd/system-generators/`
- **Type**: Directory
- **Description**: Contains custom systemd generators, which are scripts or executables that dynamically create unit files at runtime based on specific conditions.
- **Forensic Use**: Investigators can look here for custom generators that might have been added or altered to create malicious services dynamically on system boot.

### `/etc/logrotate.conf`
- **Type**: File
- **Description**: Configures log rotation schedules.
- **Forensic Use**: Examines log retention policies to ensure historical logs are available.

### `/etc/yum.conf` and `/etc/yum.repos.d/`
- **Type**: Files
- **Description**: Configures YUM package manager settings and repositories.
- **Forensic Use**: Detects modified repositories or package sources, which could indicate compromise.

### `uptime`
- **Type**: Command
- **Description**: Displays system uptime and load averages.
- **Forensic Use**: Useful for determining how long a system has been running, which can help correlate with incident timelines.

### `lsusb`
- **Type**: Command
- **Description**: Lists USB devices connected to the system.
- **Forensic Use**: Helpful in identifying unauthorized USB devices that may have been used for data exfiltration or malware introduction.

### `lspci`
- **Type**: Command
- **Description**: Lists PCI devices connected to the system.
- **Forensic Use**: Can help detect unusual hardware connected via PCI, which may be used for sniffing or other attacks.

### `rpm -qa`
- **Type**: Command (for RPM-based systems)
- **Description**: Lists all installed packages on the system.
- **Forensic Use**: Useful for identifying installed software, which may include unauthorized or malicious packages.

### `lsmod`
- **Type**: Command
- **Description**: Lists currently loaded kernel modules.
- **Forensic Use**: Important for identifying potentially malicious or unauthorized kernel modules loaded on the system.

### `systemctl list-units --type=service --all`
- **Type**: Command
- **Description**: Lists all systemd services, including inactive ones.
- **Forensic Use**: Useful for identifying persistent services, both active and inactive, that may indicate malicious configurations.

### `systemctl list-timers --all`
- **Type**: Command
- **Description**: Lists all systemd timers, including inactive ones.
- **Forensic Use**: Useful for discovering systemd timers that may execute malicious commands.

### `timedatectl`
- **Type**: Command
- **Description**: Displays and controls the system's date and time settings.
- **Forensic Use**: Can be used to verify time synchronization settings, which may be altered to evade logging mechanisms or tamper with timestamps.

### `hostnamectl`
- **Type**: Command
- **Description**: Shows or sets the system hostname and other information.
- **Forensic Use**: Useful for verifying system identification settings and detecting changes that could be an attempt to obscure the system’s identity.

### `uname -a`
- **Type**: Command
- **Description**: Displays detailed system information, including the kernel version and architecture.
- **Forensic Use**: Useful for identifying the operating system and kernel version, which helps determine vulnerabilities and locate appropriate log files or artifacts.

### `/proc/modules`
- **Type**: File
- **Description**: Lists all currently loaded kernel modules along with information on dependencies and memory usage.
- **Forensic Use**: Useful for identifying loaded modules that could indicate rootkits or other malicious kernel-level modifications.

### `/proc/cmdline`
- **Type**: File
- **Description**: Displays the boot parameters passed to the kernel at startup.
- **Forensic Use**: Helps investigators identify any unusual boot parameters that could indicate tampering with the boot process.

### `/proc/mounts`
- **Type**: File
- **Description**: Lists currently mounted filesystems, showing mount points and associated options.
- **Forensic Use**: Useful for examining mounted filesystems and detecting unauthorized or suspicious mounts.

### `/proc/version`
- **Type**: File
- **Description**: Provides kernel version information, along with the compiler used to build the kernel.
- **Forensic Use**: Helps confirm kernel version, which can be cross-referenced with known vulnerabilities.

### `/proc/swaps`
- **Type**: File
- **Description**: Shows active swap files and devices used by the system.
- **Forensic Use**: Useful for checking swap usage, which could contain evidence of previous activity or be abused for hiding data.

### `/proc/sys`
- **Type**: Directory
- **Description**: Contains files representing kernel parameters, often adjustable at runtime to change system behavior.
- **Forensic Use**: Investigators can examine system parameters for security-related settings, which may have been modified by attackers to weaken defenses.

### `/proc/filesystems`
- **Type**: File
- **Description**: Lists supported filesystem types recognized by the kernel.
- **Forensic Use**: Useful for verifying filesystem support, especially if unusual or custom filesystems are being used by an attacker.

### `/proc/uptime`
- **Type**: File
- **Description**: Displays the system uptime and idle time.
- **Forensic Use**: Helpful for understanding system uptime in relation to incident timelines and determining reboot or boot times.

### `/proc/kallsyms`
- **Type**: File
- **Description**: Lists all symbols in the kernel, which includes addresses of kernel functions and variables.
- **Forensic Use**: Useful for advanced kernel analysis, potentially identifying kernel modifications or malicious code.
---

## System Logs

### `/var/log/secure` (or `/var/log/auth.log`)
- **Type**: File
- **Description**: Logs authentication-related events.
- **Forensic Use**: Tracks login attempts, privilege escalations, and unauthorized access.

### `/var/log/messages` (or `/var/log/syslog`)
- **Type**: File
- **Description**: General system logs.
- **Forensic Use**: Reveals various system activities and events for broad analysis.

### `/var/log/lastlog`
- **Type**: File
- **Description**: Contains last login information for each user.
- **Forensic Use**: Helps establish user activity or inactivity on the system.

### `/var/log/wtmp`
- **Type**: File
- **Description**: Logs all login and logout sessions.
- **Forensic Use**: Useful for creating a timeline of user sessions and identifying account usage patterns.

### `/var/log/btmp`
- **Type**: File
- **Description**: Records failed login attempts.
- **Forensic Use**: Detects brute-force attacks or unauthorized access attempts.

### `/var/log/audit`
- **Type**: File
- **Description**: Logs events from the Linux Audit Framework.
- **Forensic Use**: Provides detailed event logging for security monitoring and policy compliance.

### `/var/log/cron`
- **Type**: File
- **Description**: Logs cron jobs and scheduled tasks.
- **Forensic Use**: Helps identify scheduled tasks and their frequency, potentially revealing unauthorized jobs.

### `/var/log/laurel`
- **Type**: File
- **Description**: Often used to log information related to specific software or custom applications.
- **Forensic Use**: May contain logs for specific services or applications, useful in application-level investigations.

---

## User Analysis

### `~/.bash_history`
- **Type**: File
- **Description**: Stores a history of commands executed by users in the Bash shell.
- **Forensic Use**: Shows user actions and can reveal suspicious command usage.

### `~/.bashrc`
- **Type**: File
- **Description**: User-specific shell configuration file.
- **Forensic Use**: May reveal malicious environmental changes or configurations.

### `~/.profile`
- **Type**: File
- **Description**: Executed at login for user environment setup.
- **Forensic Use**: Reveals environment configurations which may have been altered for persistence.

### `~/.ssh/authorized_keys`
- **Type**: File
- **Description**: Contains SSH keys authorized for remote access.
- **Forensic Use**: Identifies unauthorized SSH keys added for backdoor access.

### `~/.config/autostart`
- **Type**: Directory
- **Description**: Contains application files that automatically start when a user logs in.
- **Forensic Use**: Identifies potentially malicious programs configured to persist on startup.

### `~/.bash_logout`
- **Type**: File
- **Description**: Contains commands executed when a user logs out.
- **Forensic Use**: Can reveal custom or suspicious actions triggered upon logout.

### `~/.bash_profile`
- **Type**: File
- **Description**: User-specific environment and startup script, executed at login.
- **Forensic Use**: Tracks user-defined environment variables or commands that could establish persistence.

### `*.history`
- **Type**: File
- **Description**: Command history files for various shells (e.g., `.zsh_history`, `.bash_history`).
- **Forensic Use**: Provides a record of commands executed by the user across different shells.

### `~/.viminfo`
- **Type**: File
- **Description**: Stores information on files and data from previous Vim sessions.
- **Forensic Use**: Can reveal filenames and command sequences used in previous text editing sessions.

### `last`
- **Type**: Command
- **Description**: The **`last`** command shows a listing of the most recent user logins and system reboots. It reads from the **`/var/log/wtmp`** file.
- **Forensic Use**: Useful for identifying when a user logged in or out of the system, as well as when the system was rebooted. It can be used to corroborate user login activity with other logs.

### `lastlog`
- **Type**: Command
- **Description**: The **`lastlog`** command displays the most recent login information for all users on the system, including the last login time and the originating IP address.
- **Forensic Use**: Useful for identifying abnormal or unauthorized logins, especially when cross-referenced with other user activity logs or system logs.

### `who -H`
- **Type**: Command
- **Description**: The **`who -H`** command shows information about who is logged into the system, including the login time, terminal, and IP address (if applicable). The **`-H`** flag adds headers to the output, making it easier to read.
- **Forensic Use**: Provides real-time information about who is logged into the system, which can be helpful for identifying unauthorized logins or tracking legitimate user activity.

### `w`
- **Type**: Command
- **Description**: The **`w`** command provides a summary of who is logged in and what they are doing, including the current processes they are running.
- **Forensic Use**: Similar to **`who -H`**, but with additional details about the user’s activity. It can be useful for monitoring active sessions and identifying suspicious or unexpected processes running under a user’s session.
---


## Network Artifacts

### `netstat -tulnp`
- **Type**: Command
- **Description**: Shows active TCP/UDP network connections and listening ports.
- **Forensic Use**: Identifies suspicious open ports and connections.

### `ss -tulnp`
- **Type**: Command
- **Description**: Provides socket status, similar to `netstat`.
- **Forensic Use**: Analyzes active network connections and services.

### `iptables -L\iptables-save`
- **Type**: Command
- **Description**: Lists current firewall rules.
- **Forensic Use**: Reveals firewall configurations that could indicate blocked or allowed connections.

### `arp -a`
- **Type**: Command
- **Description**: Displays the system’s ARP table.
- **Forensic Use**: Identifies network devices and IP-to-MAC mappings, useful for network reconnaissance detection.

### `ip neigh show`
- **Type**: Command
- **Description**: Displays ARP table for IPv4 and neighbor cache for IPv6.
- **Forensic Use**: Helps identify nearby hosts and IP associations in the network.

### `ip route show`
- **Type**: Command
- **Description**: Shows routing table information.
- **Forensic Use**: Provides insight into network routes and possible configurations for malicious redirections.

### `ifconfig`
- **Type**: Command
- **Description**: Displays network interface configuration.
- **Forensic Use**: Shows IP addresses, MAC addresses, and network status for each interface, aiding in network investigation.

---

## Filesystem Analysis

### `find / -type f -executable`
- **Type**: Command
- **Description**: Lists all executable files on the system.
- **Forensic Use**: Helps locate unknown executables that could be malicious.

### `find / -type f -executable -mtime`
- **Type**: Command
- **Description**: Finds executable files that have been modified recently (with a customizable time argument).
- **Forensic Use**: Useful for tracking recently modified executables, which may indicate suspicious activity.

### `find / -type f -exec ls -lh {} \;`
- **Type**: Command
- **Description**: Lists all files with details like size, ownership, and permissions.
- **Forensic Use**: Useful for searching files with specific criteria such as modification or access times.

### `find / -type f -mtime -7`
- **Type**: Command
- **Description**: Finds files modified in the last 7 days (customizable).
- **Forensic Use**: Tracks recent file modifications for suspicious activity.

### `find / -type f -atime -7`
- **Type**: Command
- **Description**: Finds files accessed in the last 7 days (customizable).
- **Forensic Use**: Tracks recent file access events.

### `find / -type f -executable -print0 2>/dev/null | xargs -0 sha256sum 2>/dev/null`
- **Type**: Command
- **Description**: Finds all executable files in the filesystem and generates a SHA-256 hash for each, providing a quick way to catalog executables.
- **Forensic Use**: Useful for quickly generating hashes of all executables on the system for integrity checking or comparison against known good hashes.

### `find / -name ".*"`
- **Type**: Command
- **Description**: Finds all hidden files and directories (those starting with a dot).
- **Forensic Use**: Helps identify hidden files or directories that might be used to conceal malicious files or configurations.

### `lsof`
- **Type**: Command
- **Description**: Lists open files and the processes that opened them.
- **Forensic Use**: Useful for identifying files that are currently open, even if they are deleted from the filesystem. This can help recover files that are still in memory but no longer on disk.

---

## Process and Memory

### `/proc/<pid>/cmdline`
- **Type**: File
- **Description**: Contains the command line arguments of a running process.
- **Forensic Use**: Reveals specific commands and arguments used by processes, which can indicate malicious behavior.

### `/proc/<pid>/exe`
- **Type**: Symlink
- **Description**: Points to the executable file of the process.
- **Forensic Use**: Verifies the location and name of the executable, identifying potentially suspicious programs.

### `/proc/<pid>/fd`
- **Type**: Directory
- **Description**: Lists all file descriptors opened by the process.
- **Forensic Use**: Shows files, network sockets, and other resources accessed by a process. It can also be used for recovering files that are still open but have been deleted from disk.

### `/proc/<pid>/environ`
- **Type**: File
- **Description**: Contains the environment variables for the process.
- **Forensic Use**: Analyzes the environment settings of a process, which may include maliciously set variables.

### `/proc/<pid>/maps`
- **Type**: File
- **Description**: Displays memory mappings of the process.
- **Forensic Use**: Provides insight into libraries and files mapped into process memory, which may indicate injected or malicious code.

### `/proc/<pid>/status`
- **Type**: File
- **Description**: Shows detailed status information about the process, including owner, memory usage, and process state.
- **Forensic Use**: Useful for analyzing process attributes and resource usage, identifying suspicious or resource-heavy processes.

### `/proc/<pid>/net`
- **Type**: Directory
- **Description**: Contains network-related information about the process (e.g., connections and listeners).
- **Forensic Use**: Tracks active network connections specific to a process, useful in identifying suspicious network activity.

### `ps -eF`
- **Type**: Command
- **Description**: Lists all running processes with detailed information including process ID, parent ID, and the command that started each process.
- **Forensic Use**: Helps in tracking all active processes and understanding their relationships and resource usage.

### `ls -alR /proc/*/exe 2> /dev/null | grep deleted`
- **Type**: Command
- **Description**: Finds processes with executables that have been deleted from disk but are still running in memory.
- **Forensic Use**: Identifies processes that are running from deleted binaries, a potential indicator of rootkits or other forms of malware.

---