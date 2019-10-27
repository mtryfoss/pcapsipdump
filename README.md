# pcapsipdump
Fork of http://pcapsipdump.sourceforge.net/

Build
git clone https://github.com/mtryfoss/pcapsipdump
cd pcapsipdump
make
make install

Usage
Usage: pcapsipdump [-fpUt] [-i <interface> | -r <file>] [-d <working directory>]
                   [-v level] [-R filter] [-m filter] [-n filter] [-l filter]
                   [-B size] [-t trigger:action:param] [expression]
 -f   Do not fork or detach from controlling terminal.
 -p   Do not put the interface into promiscuous mode.
 -U   Make .pcap files writing 'packet-buffered' - slower method,
      but you can use partitially written file anytime, it will be consistent.
 -i   Specify network interface name (i.e. eth0, em1, ppp0, etc).
 -r   Read from .pcap file instead of network interface.
 -v   Set verbosity level (higher is more verbose).
 -B   Set the operating system capture buffer size, a.k.a. ring buffer size.
      This can be expressed in bytes/KB(*1000)/KiB(*1024)/MB/MiB/GB/GiB. ex.: '-B 64MiB'
      Set this to few MiB or more to avoid packets dropped by kernel.
 -R   RTP filter. Specifies what kind of RTP information to include in capture:
      'rtp+rtcp' (default), 'rtp', 'rtpevent', 't38', or 'none'.
 -m   Method-filter. Default is '^(INVITE|OPTIONS|REGISTER)$'
 -n   Number-filter. Only calls to/from specified number will be recorded
      Argument is a regular expression. See 'man 7 regex' for details.
 -l   Record only each N-th call (i.e. '-l 3' = record only each third call)
      For the expression syntax, see 'man 7 pcap-filter'
 -d   Set directory/filename template, where captured files will be stored.
      ex.: -d /var/spool/pcapsipdump/%Y%m%d/%H/%Y%m%d-%H%M%S-%f-%t.pcap
 -t   <trigger>:<action>:<parameter>. Parameter is %-expanded (see below)
      Triggers: open = when opening a new .pcap file; close = when closing
      Actions and their parameters:
      mv:<directory> - move .pcap files to <directory> (using /bin/mv)
      exec:"/bin/blah args..." - fork and execute /bin/blah with arguments
      sh:"shell code" - fork and execute /bin/sh -c "shell code"
Following %-codes are expanded in -d and -t: %f (from/caller), %t (to/callee),
%i (call-id), and call date/time (see 'man 3 strftime' for details)
    
