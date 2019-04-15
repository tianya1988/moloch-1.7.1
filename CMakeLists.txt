cmake_minimum_required(VERSION 3.13)
project(moloch C)

set(CMAKE_C_STANDARD 11)

include_directories(/home/jason/Downloads/thirdpatry/libpcap-1.9.0)
include_directories(/home/jason/Downloads/thirdpatry/curl-7.61.1)


include_directories(capture)
include_directories(capture/parsers)
include_directories(capture/plugins/lua)
include_directories(capture/thirdparty)

include_directories(/usr/local/include/glib-2.0)
include_directories(/usr/local/lib/glib-2.0/include)
link_directories(/usr/local/lib)


add_executable(moloch
        capture/parsers/dhcp.c
        capture/parsers/dns.c
        capture/parsers/http.c
        capture/parsers/irc.c
        capture/parsers/krb5.c
        capture/parsers/ldap.c
        capture/parsers/misc.c
        capture/parsers/mysql.c
        capture/parsers/oracle.c
        capture/parsers/postgresql.c
        capture/parsers/quic.c
        capture/parsers/radius.c
        capture/parsers/smb.c
        capture/parsers/smtp.c
        capture/parsers/socks.c
        capture/parsers/ssh.c
        capture/parsers/tds.c
        capture/parsers/tls-cipher.h
        capture/parsers/tls.c
        capture/plugins/daq/reader-daq.c
        capture/plugins/lua/data.c
        capture/plugins/lua/httpService.c
        capture/plugins/lua/molua.c
        capture/plugins/lua/molua.h
        capture/plugins/lua/session.c
        capture/plugins/pfring/reader-pfring.c
        capture/plugins/snf/reader-snf.c
        capture/plugins/netflow.c
        capture/plugins/scrubspi.c
        capture/plugins/suricata.c
        capture/plugins/tagger.c
        capture/plugins/wise.c
        capture/plugins/writer-s3.c
        capture/thirdparty/http_parser.c
        capture/thirdparty/http_parser.h
        capture/thirdparty/js0n.c
        capture/thirdparty/patricia.c
        capture/thirdparty/patricia.h
        capture/bsb.h
        capture/config.c
        capture/db.c
        capture/dll.h
        capture/drophash.c
        capture/field.c
        capture/hash.h
        capture/http.c
        capture/main.c
        capture/moloch.h
        capture/packet.c
        capture/parsers.c
        capture/plugins.c
        capture/reader-libpcap-file.c
        capture/reader-libpcap.c
        capture/reader-null.c
        capture/reader-tpacketv3.c
        capture/readers.c
        capture/rules.c
        capture/session.c
        capture/trie.c
        capture/writer-disk.c
        capture/writer-inplace.c
        capture/writer-null.c
        capture/writer-simple.c
        capture/writers.c
        capture/yara.c
        contrib/decodeDrops.c
        tests/plugins/test.c)
