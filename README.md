# libwireshark library decoded data
Using libwireshark library to decode packet, the decoded data is stored in `struct epan_dissect`.

#Dependencies
* libwireshark library (version 1.12.8)

* libglib2.0

# Install
- ubuntu
```
apt-get install libglib2.0-dev

git clone https://github.com/sunwxg/decode_by_libwireshark.git

cd decode_by_libwireshark
cat libs/libwireshark.{00,01,02,03} > libs/libwireshark.so
chmod 775 libs/libwireshark.so

make

./myshark -f file.pcap
```

# Debug
Debug program to see how wireshark dissect packet.
- Download wireshark source code(version 1.12.8) from www.wireshark.org
- Uncompress source code and compile. Following [wireshark guide](https://www.wireshark.org/docs/wsug_html/#ChBuildInstallUnixBuild)
- Export SRC_WIRESHARK as wireshark source code path
```
export SRC_WIRESHARK=<wireshark source code path>
```
- Make file
```
make debug
```
- Using GDB
```
libtool --mode=execute gdb ./myshark
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
