# DECHAP

dechap is a tool which attempts to recover login credentials from captured
PPPoE, RADIUS and L2TP CHAP authentications plus MD5 authenticated OSPF or BGP
traffic. It strips away any 802.1Q tags and / or MPLS labels which are present
to get to the good stuff and then runs a dictionary attack against any
authentications it finds.

Please see http://networkingbodges.blogspot.com/ for more information on the
theory behind this if you are interested.


### INSTALLATION

Provided the OpenSSL dev libraries are installed it should be possible to simply
extract the source code, cd into the directory then run `make`.


### USAGE

There are only two parameters and both are mandatory. You must specify your
capture file (original pcap format) with the `-c` flag and your word list with
the `-w` flag. Here's an example:

```
lab@lab:~/dechap$ ./dechap -w mywords.txt -c someauths.cap
Found password "tangerine" for user user1@testisp.com.
Unable to find a password for user user2@testisp.com.
Found password "password1" for user user3@testisp.com.
Found password "Africa" for user user4@testisp.com.
Found password "Frankenstein" for user user5@testisp.com.
Found password "s3cr3tk3y" for OSPF host 10.1.1.1 key 1.
Found password "t1nt3rn3t" for TCP from 10.0.0.2 to 10.0.0.1.
lab@lab:~/dechap$
```


### CHANGE LOG

- v0.1a: First working release, only works with PPPoE traffic.

- v0.2a: Added support for RADIUS and L2TP captures.
         Fixed a bug in MPLS decap.

- v0.3a: Added support for MD5 authenticated OSPF.

- v0.4a: Added support for MD5 authenticated BGP.

- v0.5a: Fixed Makefile.


### Credits

dechap v0.1 to v0.4 Alpha - Written by Foeh Mannay, October 2013
dechap v0.5 Alpha - Written by libcrack, April 2016

