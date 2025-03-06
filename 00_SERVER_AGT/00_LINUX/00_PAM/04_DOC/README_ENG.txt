========================================
           PAM MODULE README
========================================

[1] PROJECT OVERVIEW
-------------------
This project is a Linux PAM (Pluggable Authentication Module) for authentication enhancement.
It can be used in SSH, `su`, `sudo`, and other authentication processes to enforce additional security policies.

[2] PROJECT STRUCTURE
-------------------
- src/               -> Source code folder
  ├── pam_module.c   -> PAM module implementation file
  ├── pam_module.h   -> Header file
  ├── Makefile       -> Build and installation script
  ├── test/          -> Test scripts and data
  ├── docs/          -> Documentation and guides
  ├── config/        -> Example PAM configuration files
  ├── scripts/       -> Installation and uninstallation scripts
  ├── README.txt     -> This README file
  ├── LICENSE        -> License information

[3] INSTALLATION
-------------------
1. Compile the source code:
   $ make

2. Install the PAM module:
   $ sudo make install

3. Apply PAM configuration:
   Edit the `/etc/pam.d/sshd` file and add the following line:
   auth required /lib/security/pam_module.so

4. Restart SSH service:
   $ sudo systemctl restart sshd

[4] CONFIGURATION
-------------------
To apply the PAM module, modify the appropriate file in `/etc/pam.d/`.

Example (`/etc/pam.d/sshd`):
   auth required pam_unix.so
   auth required /lib/security/pam_module.so

Environment variable settings:
   export PAM_MODULE_PATH=/lib/security/pam_module.so

[5] USAGE
-------------------
1. Run SSH or `su` to check if the PAM module is applied.
2. Check logs:
   $ sudo tail -f /var/log/auth.log  (Ubuntu/Debian)
   $ sudo tail -f /var/log/secure    (RHEL/CentOS)

[6] LOGGING & DEBUGGING
-------------------
To monitor the PAM module behavior, enable `syslog`.

View logs in real time:
   $ sudo journalctl -xe | grep pam_module

[7] UNINSTALLATION
-------------------
$ sudo make uninstall

[8] LICENSE
-------------------
This project is distributed under the MIT License.

========================================
      END OF README
========================================
