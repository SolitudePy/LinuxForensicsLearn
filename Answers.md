# Chapter 3. Answers
1. Answer: The /proc filesystem is unique because it doesn’t contain actual files on disk; 
instead, it represents runtime system information in the form of virtual files. 
This is why it’s called a "pseudo-filesystem." 
When you access a file in /proc, the kernel dynamically generates the data, 
providing real-time information about system and process states. 
This is different from typical filesystems, which store persistent data.

2. The /proc/sys directory allows real-time kernel parameter tuning by providing access to various kernel and system settings. 
Changes made to these files can alter system behavior without requiring a reboot. 
For instance, /proc/sys/net/ipv4/ip_forward controls IP forwarding, 
which can be enabled for routing purposes. 
However, altering these parameters can lead to security vulnerabilities, 
such as enabling packet forwarding without adequate firewall settings, 
which can expose the system to attacks.

3. Answer: The /proc/sys/net/ipv4 directory contains configurations for IPv4 networking, affecting performance and security. For example:
ip_forward: Enabling this allows the machine to route packets, useful in routers but potentially dangerous on exposed hosts.
tcp_syncookies: Setting this to 1 enables SYN cookies, helping mitigate SYN flood attacks by preventing resource exhaustion in TCP handshakes.

4. Answer: To investigate a suspicious process, examine:
cmdline: Shows command-line arguments; unusual commands can indicate malicious behavior.
fd/: Lists open file descriptors; unusual network connections (like persistent connections to external IPs) can be suspicious.
status: Provides memory and CPU usage; high usage could indicate resource abuse.
exe: link to the original process executable even if it was deleted, useful incident response.

5. Answer: The kernel dynamically generates data in /proc files when they’re accessed. Unlike regular files, /proc files are generated on-the-fly by kernel code, pulling real-time system metrics or process information directly from memory structures. 
This design minimizes storage overhead and ensures up-to-date information.

6. Answer: /proc/kcore is a file that represents the system's physical memory as if it were a core dump, used for debugging. 
It provides access to kernel memory, but reading it can slow the system and requires root privileges, as it exposes sensitive data. 
Caution is advised due to potential security risks and system impact.

7. A: An inode is a data structure used in Linux filesystems to store information about a file or directory, 
excluding its name or its actual data. Each inode contains metadata such as the file type, 
permissions, owner, size, timestamps, and pointers to the data blocks where the file's content is stored. 
Inodes are crucial for the filesystem's ability to manage and access files efficiently.

8. The xfs_db tool is essential for low-level examination of XFS file systems, 
allowing investigators to inspect superblocks, inodes, and raw blocks. 
By converting addresses and performing block lookups, 
xfs_db helps trace data structures back to files, 
facilitating analysis of both active and deleted files on an XFS volume

9. Answer: When a file is deleted on XFS, 
its directory entry is marked as free space, 
and the inode is partially overwritten to signify deallocation. 
The ctime (change time) for the inode updates to the deletion time, 
while the file size and extent counts are zeroed out. 
However, extent data remains intact, making it possible to recover data by examining the raw inode and its extents in the absence of a dedicated undelete tool​

10. Answer: Forensic support for XFS is limited compared to EXT file systems, 
with tools like X-Ways and a development branch of Sleuthkit providing partial support. 
Given the complexity of XFS structures and limited tool compatibility, 
investigators often rely on manual methods and low-level tools like xfs_db and dd to analyze XFS systems, 
especially when dealing with deleted or hidden data.

# Chapter 4. Answers
1. Answer: A persistence mechanism is a method used by attackers to maintain access to a compromised system across reboots or updates. It's valuable because it allows the attacker to regain control without re-exploiting the system.
2. Example answers: 
Persistence techniques in Linux include:
Cron jobs: Attackers set malicious cron jobs that run periodically, ensuring re-execution at specific intervals or on reboot.
Systemd services: By creating custom or altering existing systemd service files, attackers can start malicious services automatically at boot.
rc.local modifications: Commands placed in /etc/rc.local execute on startup, though less common now in systemd-based systems. These techniques are often hard to detect without thorough monitoring of these files and services.
3. Example answer: 
Answer: With systemd services, defenders can regularly audit and review active services, searching for unknown or unexpected entries. Checking service files in /etc/systemd/system/ and /lib/systemd/system/ for unauthorized changes and comparing them with baselines helps detect alterations. Automated alerts on file modifications and enabling auditd logging for service file access further strengthen detection.
4. Answer: Overlooking persistence mechanisms can lead to an attacker’s re-entry into the system even after initial cleanup, allowing further data theft, lateral movement, or destructive actions. Persistent footholds enable attackers to bypass perimeter defenses, escalate privileges, and reestablish full control, causing prolonged security risks and potential reputational damage.
5. Answer: Both LD_PRELOAD and ld.so.preload allow attackers to load malicious shared libraries before standard libraries during program execution. This enables them to intercept function calls and alter the behavior of applications without modifying the binaries themselves. The security implications are significant, as these methods can evade detection by traditional security measures. For defenders, monitoring ld.so.preload and checking for unauthorized shared libraries can help identify potential compromises.

# Chapter 5. Answers
1. Answer: Example:
/proc/modules: Used to detect loaded kernel modules, which may include rootkits in a compromised system. For example, an investigator might find an unknown module loaded, which could point to a hidden malicious process.
/etc/sshd_config: Useful for examining SSH settings to check for altered configurations. For example, if PermitRootLogin is set to "yes" on a production server, this could indicate that unauthorized remote access was enabled.
/var/log/auth.log: Monitors authentication attempts. If logs show repeated failed login attempts from an unfamiliar IP, this could suggest a brute-force attack.
uptime: Can help correlate system uptime with an incident timeline, such as a recent reboot after malware installation.
lsmod: Detects loaded kernel modules, which might reveal malicious drivers. For example, an investigator might find a module with no associated file on disk, indicating a possible rootkit.
2. Answer:
ss: Useful for quickly accessing real-time socket information, providing detailed data on active connections. This is particularly valuable when monitoring a live system with high network traffic.
netstat: Offers insights into network connections by querying information stored in /proc, useful for both real-time and historical analysis.
Comparison Utility: Comparing ss and netstat outputs can help verify accuracy, detect discrepancies, and identify connections or services that may appear in one output but not the other—an indication of stealthy connections or tampering.
3. Answer:
Purpose: lsof lists open files and associated processes, making it essential for identifying files that are open even if deleted, as well as for monitoring files tied to specific network connections.
Scenario: During an investigation, lsof could expose files open by processes communicating with suspicious IPs, potentially identifying data exfiltration or malicious scripts running in memory despite deletion from disk.
4. Answer:
Example:
Artifacts:
/var/log/secure(or auth.log): Shows authentication attempts, highlighting brute-force attacks or repeated login failures.
lastlog: Lists last login information, allowing for detection of unusual access based on time, source, and user.
who command: Lists currently logged-in users, enabling real-time checks for unauthorized active sessions.