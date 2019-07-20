# sqrl-libpam
A sample project trying to build a Pam module

Building the PAM module and installing it on your system.
```
sudo apt install autoconf automake make libtool libpam0g-dev
autoreconf -i
make 
sudo make install
```

Adding this line to your PAM configuration will require you to login with SQRL
```
auth        required      /usr/local/lib/security/pam_sqrl_login.so
```
