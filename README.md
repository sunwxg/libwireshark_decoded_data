# libwireshark library decoded data
Using libwireshark library to decode packet, the decoded data is stored in `struct epan_dissect`.

# Dpendencies
* libwireshark library (version 2.4.4)

* libglib2.0

# Install
- openSUSE
```
zypper in wireshark
zypper in glib2 glib2-devel
zypper in libwiretap7 libwsutil8 libwireshark9

make source
make

./myshark -f file.pcap
```

# Output
```
[ip]
. [ip.version] 4
. [ip.hdr_len] 20
. [ip.dsfield] 160
. . [ip.dsfield.dscp] 40
. . [ip.dsfield.ecn] 0
. [ip.len] 164
. [ip.id] 0
. [ip.flags] 2
. . [ip.flags.rb] 0
. . [ip.flags.df] 1
. . [ip.flags.mf] 0
. [ip.frag_offset] 0
. [ip.ttl] 254
. [ip.proto] 132
. [ip.checksum] 40188
. . [ip.checksum_good] 0
. . [ip.checksum_bad] 0
. [ip.src] 10.128.229.6
. [ip.addr] 10.128.229.6
. [ip.src_host] 10.128.229.6
. [ip.host] 10.128.229.6
. [ip.dst] 10.128.228.50
. [ip.addr] 10.128.228.50
. [ip.dst_host] 10.128.228.50
. [ip.host] 10.128.228.50
```
