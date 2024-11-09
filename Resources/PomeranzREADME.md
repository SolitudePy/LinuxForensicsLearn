Copyright © Hal Pomeranz
This material is distributed under the terms of the 
Creative Commons Attribution-ShareAlike 4.0 International License
http://creativecommons.org/licenses/by-sa/4.0/


ABOUT:
======

This is a four-day course in Linux Forensics. It covers:

   -- Live system capture and triage with UAC
   -- Memory capture and analysis
   -- Mounting and triage of Linux disk images
   -- File system timeline analysis
   -- Log file analysis
   -- Analysis of user artifacts
   -- EXT and XFS file system forensics

The course is divided into modules and there is a hands-on lab
exercise after each module. Labs are completed inside of a Linux
virtual machine image, which is provided with the course materials.


COURSE DATA:
============

PomeranzLinuxForensics.pdf -- Class slides with instructor notes

LinuxForensicsLabVM -- Directory containing CentOS Linux virtual
   machine with lab exercises and images. Login as user "lab" with
   the password "linuxforensics". The root password is also
   "linuxforensics", and user "lab" has Sudo access.

Exercises -- Directory containing lab exercises for the course in
   HTML format. A copy of this directory is also in the home directory
   for the "lab" user inside the lab virtual machine.

VERSION-*.txt -- Checksums for all files included here. Use bitfit.py
   for automated validation (https://github.com/joswr1ght/bitfit).


CONTACTS:
=========

Download updates from https://archive.org/details/HalLinuxForensics

Hal Pomeranz			
hrpomeranz@gmail.com
@hal_pomeranz@infosec.exchange


THANKS:
=======

Ali Hadi (@binaryz0ne) and the team at Champlain College created Linux
forensic images for a workship at OSDFCon 2019.  I would like to thank
them for allowing me to use them in this course. You will find the
images and other material under /images/All-Images/AliHadi-OSDF inside
the lab virtual machine. These files are also available from
https://github.com/ashemery/LinuxForensics

Tyler Hudak (@SecShoggoth) gave the community UAC, memory, and disk images
from a compromised honeypot. We will be using this data in the course.
You will find the images under /images/All-Images/HudaksHoneypot inside
the lab virtual machine. Blog posts based on my own investigation of these
images at https://righteousit.wordpress.com/2021/12/20/hudaks-honeypot-part-1/
