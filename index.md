---
layout: default
title: Home
permalink: /
---

# Linux Forensics Study Guide
```
Welcome to the Linux Forensics study guide! 
This document will help you navigate through the necessary topics, 
materials, and exercises to build a solid foundation in Linux forensics. 
Follow the outlined steps, explore the materials provided, 
and feel free to ask questions as you go. 
Currently this guide does not explore Memory Forensics
Remember to document your answers and reflections along the way, Let’s dive in!

Resources:
Download these: LinuxForensicsLabVM/, Exercises/, PomeranzLinuxForensics.pdf, README.txt
https://archive.org/download/HalLinuxForensics/media-v3.0.2/

Challenges:
https://cyberdefenders.org/blueteam-ctf-challenges/?content=free&categories=endpoint-forensics&os=Linux
```

# Chapter 1. Linux Directories 

<a href="Subjects/1. Linux Directories/index.html" target="_blank">Linux Directory Structure By https://dev.to/softwaresennin</a><br>
<a href="Resources/PomeranzLinuxForensics.pdf#page=15" target="_blank">PomeranzLinuxForensics page 15-20 By Hal Pomeranz</a>


## Tasks
1. What is the difference between a hard link and a symbolic(soft) link?
2. what is the relationship of /bin and /usr/bin, /sbin and /usr/sbin?
3. what is usually saved in /etc? name 3 forensic artifacts in /etc.
4. what is usually saved in /var/log? 
5. what is special about the /tmp directory, why as forensic analysts we would want to check it? 

# Chapter 2. Linux Logs
<a href="Subjects/2. Linux Logs/Logs.html" target="_blank">Linux Logs guide</a><br>
<a href="Subjects/2. Linux Logs/Linux_Auditd_For_ThreatDetection_IzyKnows_Part1.pdf" target="_blank">Linux Audit Subsystem Part 1 By IzyKnows</a><br>
<a href="Subjects/2. Linux Logs/Linux_Auditd_For_ThreatDetection_IzyKnows_Part2.pdf" target="_blank">Linux Audit Subsystem Part 2 By IzyKnows</a><br>
<a href="Subjects/2. Linux Logs/Linux_Auditd_For_ThreatDetection_IzyKnows_Part3.pdf" target="_blank">Linux Audit Subsystem Part 3 By IzyKnows</a><br>
<a href="Subjects/2. Linux Logs/LAUREL_README.html" target="_blank">LAUREL_README By https://github.com/threathunters-io/laurel</a><br>
<a href="Subjects/2. Linux Logs/laurel-about.7.html" target="_blank">laurel-about.7.md By https://github.com/threathunters-io/laurel</a><br>
<a href="Subjects/2. Linux Logs/laurel.8.html" target="_blank">laurel.8.md By https://github.com/threathunters-io/laurel</a><br>


## Tasks
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
<a href="Subjects/3. Linux FileSystems/procfs.html" target="_blank">procfs</a><br>
<a href="Subjects/3. Linux FileSystems/sysfs/sysfs.html" target="_blank">sysfs</a><br>
<a href="Subjects/3. Linux FileSystems/What_Are_inodes_linux.pdf" target="_blank">inodes</a><br>
<a href="Resources/PomeranzLinuxForensics.pdf#page=169" target="_blank">PomeranzLinuxForensics page 169-181 By Hal Pomeranz</a><br>
<a href="Resources/PomeranzLinuxForensics.pdf#page=182" target="_blank">PomeranzLinuxForensics page 182 (Exercise 16) By Hal Pomeranz</a>


## Tasks
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
11. What is the purpose of the /sys directory in Linux? How does it differ from /proc?

# Chapter 4. Linux Attacks Techniques
<a href="Subjects/4. Linux Attacks Techniques/Art-of-Linux-Persistence.pdf" target="_blank">Linux Persistence By hadess</a><br>
<a href="Subjects/4. Linux Attacks Techniques/linux-persistence-map.pdf" target="_blank">Linux Persistence Map</a>


## Tasks
1. What is a persistence mechanism, and why is it valuable to attackers?
2. List and explain three common persistence mechanisms discussed in the article.
3. Choose one persistence mechanism and detail steps defenders can take to detect and mitigate it on Linux systems.
4. Discuss the potential impact of overlooking persistence mechanisms during a Linux incident response. What risks might this pose?
5. Explain how LD_PRELOAD and ld.so.preload can be used as persistence mechanisms in Linux. What are the security implications of these techniques?


# Chapter 5. Linux Artifacts & Live Response
<a href="Subjects/5. Linux Artifacts & Live Response/Artifacts.html" target="_blank">Linux Artifacts guide</a><br>
<a href="Resources/PomeranzLinuxForensics.pdf#page=5" target="_blank">PomeranzLinuxForensics page 5-13(including Exercise) By Hal Pomeranz</a><br>
<a href="Resources/PomeranzLinuxForensics.pdf#page=25" target="_blank">PomeranzLinuxForensics Honeypot Lab Part 1 By Hal Pomeranz</a><br>
<a href="Resources/PomeranzLinuxForensics.pdf#page=35" target="_blank">PomeranzLinuxForensics Honeypot Lab Part 2 By Hal Pomeranz</a><br>
<a href="Resources/PomeranzLinuxForensics.pdf#page=49" target="_blank">PomeranzLinuxForensics Honeypot Lab Part 3 By Hal Pomeranz</a>


## Tasks
1. Choose 5 artifacts and explain their forensic usage with real-world examples.
2. An investigator notices that both ss and netstat commands are used in Linux network analysis. What could be the advantages of using each command in forensic investigations? Describe the usefulness of comparing the outputs of both commands in identifying suspicious activity.
3. Explain the purpose of `lsof` in forensic investigations and describe a situation where lsof might be crucial in a Linux forensic analysis.
4. User login information is critical for tracking user activity. Choose three artifacts from the list that log user activity and explain how each could help determine whether unauthorized access has occurred.
5. Read about OSQuery, why is it useful for live response & monitoring in linux?
6. Try your way around UAX(Unix-like Artifact Collector) and explore the artifacts.
7. Run Plaso on UAC output.

# Chapter 6. Linux Bonus
<a href="Resources/ulk3.pdf" target="_blank">Understanding the Linux Kernel</a><br>
<a href="Subjects/6. Linux Bonus/How does ltrace work_ _ Packagecloud Blog.html" target="_blank">How does ltrace work By Joe Damato</a><br>
<a href="Subjects/6. Linux Bonus/Linux Boot Process – What Happens when Booting RHEL.html" target="_blank">Linux Boot Process By Kedar Makode</a><br>
<a href="Subjects/6. Linux Bonus/Linux Attack Techniques_ Dynamic Linker Hijacking with LD Preload.html" target="_blank">Dynamic Linker Hijacking By jbowen@cadosecurity.com</a><br>


**Read about the following**
* Linux bootloader
* Ptrace
* Linux Syscalls
* Linux Signals
* setuid,setgid, sticky bit file permissions


# Answers
Review your answers in:
<a href="Answers.html" target="_blank">Answers</a>