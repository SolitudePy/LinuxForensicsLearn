# Welcome to the Linux Forensics study guide! 
# This document will help you navigate through the necessary topics, 
# materials, and exercises to build a solid foundation in Linux forensics. 
# Follow the outlined steps, explore the materials provided, 
# and feel free to ask questions as you go. Let’s dive in!

# Chapter 1. - Linux Directories 
## linux-directories by dev.to in Subjects/1.Linux Directories/index.html
## PomeranzLinuxForensics.pdf page 15-20

# Chapter 1. - Questions
1. What is the difference between a hard link and a symbolic(soft) link?
2. what is the relationship of /bin and /usr/bin, /sbin and /usr/sbin?
3. what is usually saved in /etc? name 3 forensic artifacts in /etc.
4. what is usually saved in /var/log? 
5. what is special about the /tmp directory, why as forensic analysts we would want to check it? 

# Chapter 2. Linux Logs
## Logs.md in Subjects/2.Linux Logs/Logs.md
## Linux Audit Subsystem by IzyKnows Part 1-3 in Subjects/2.Linux Logs/*
## Laurel resources(LAUREL_README.md, laurel.8.md, laurel-about.7.md)

# Chapter 2. Questions
1. Explain the difference between utmp, wtmp, btmp and lastlog files.
2. What command can be used to format btmp you acquired from other system? 
3. What does the /var/log/cron file track, and why is it important?
4. Explain the purpose of auditd and the types of events it logs.
5. What is Laurel? why is it useful?
6. What is the significance of persistent vs. volatile storage in the context of systemd journal logs?
7. What is the role of rsyslog in managing log files? What is Syslog?
8. If you suspect unauthorized access to your system, which logs would you check first?
9. Describe a method for correlating events across different log files.
10. Discuss how log tampering can affect incident response. 
   What techniques can an attacker use to modify or delete log entries, 
   and how would you detect such tampering? Give atleast 3 tamper techniques and 2 security techniques.

# Chapter 3. Linux FileSystems
## procfs - _proc.html in Subjects/3.Linux FileSystems/_proc.html
## inodes - What_Are_inodes_linux.pdf in Subjects/3.Linux FileSystems/What_Are_inodes_linux.pdf
## XFS - XFS Filesystem in PomeranzLinuxForensics.pdf (page 169-181)
## XFS Archeology - PomeranzLinuxForensics.pdf Page 182 + LinuxForensicsLab VM

# Chapter 3. Questions
1. Explain how the /proc filesystem differs from other filesystems in Linux. 
   Why is it considered a "pseudo-filesystem"?
2. Describe the purpose of the /proc/sys directory. How does this directory enable kernel parameter tuning, 
   and what are some potential security implications of modifying files within it?
3. Explain the purpose of the /proc/sys/net/ipv4 directory. 
   How could configurations within this directory impact network performance and security? 
   Describe two settings that a system administrator might modify and the effects they would have.
4. The /proc filesystem contains process-specific directories named by their PID (process ID). 
   Describe how you could use the contents of these directories to investigate a process that is suspected to be malicious. 
   What files would you examine, and what indicators would suggest suspicious behavior?
5. How is data generated when you read files in /proc? Explain the kernel’s role in this process.
6. What is /proc/kcore, and what purpose does it serve? Why should accessing this file be handled with caution?
7. What is an inode, and what role does it play in the Linux filesystem?
8. How can forensic investigators access and analyze XFS structures?
9. What happens to data on XFS when files are deleted?
10. What limitations exist for XFS in forensic investigations?

# Chapter 4. Linux Artifacts
# Add artifacts here<>

# Chapter 5. Linux Attack Techniques
## Persistence mechanism in Subjects/5.Linux Attacks Techniques/Persistence.html(ignore the tasks)

# Chapter 6. Linux internals
ptrace implementations(strace, ltrace)
login mechanism 
services 
boot mechanism 
signals
syscalls 
suid

	