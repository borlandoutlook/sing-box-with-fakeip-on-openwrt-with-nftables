# 科学上网透明网关sing-box-with-fakeip-on-openwrt-with-nftables
需要在OpenWrt上设置一个vpn(tun0)接口，然后通过nft实现分流，即访问中国区的IP地址时直接通过wan口，访问其他IP地址时通过tun0口。
具体的操作步骤如下：
1. 用官方的VERSION="22.03.5"的OpenWrt版本，装上kmod-tun
    - (/sing-box目录是工作目录,eth1是Wan口)
2. 去sing-box github release里下载二进制程序，放到/sing-box，我的sing-box config.json如下
```
{
  "log": {
  "disabled": true
  },
  "dns": {
    "servers": [
      {
        "tag": "google",
        "address": "tls://8.8.8.8"
      },
      {
        "tag": "local",
        "address": "223.5.5.5",
        "detour": "direct"
      },
      {
        "tag": "remote",
        "address": "fakeip"
      },
      {
        "tag": "block",
        "address": "rcode://success"
      }
    ],
    "rules": [
      {
        "geosite": "category-ads-all",
        "server": "block",
        "disable_cache": true
      },
      {
        "outbound": "any",
        "server": "local"
      },
      {
        "geosite": "cn",
        "server": "local"
      },
      {
        "query_type": [
          "A",
          "AAAA"
        ],
        "server": "remote"
      }
    ],
    "fakeip": {
      "enabled": true,
      "inet4_range": "198.18.0.0/15"
    },
    "independent_cache": true,
    "strategy": "ipv4_only"
  },
  "inbounds": [
    {
      "type": "tun",
      "inet4_address": "172.19.0.1/30",
      "auto_route": true,
      "sniff": true,
      "strict_route": true,
      "stack": "system"
    }
  ],
  "outbounds": [
    {
      "type": "hysteria",
      "tag": "hysteria-out",
      "server": "xx.xx.xx.xx",
      "server_port": xxxx,
      "up_mbps": 300,
      "down_mbps": 600,
      "auth_str": "********",
      "tls": {
        "enabled": true,
        "server_name": "/CN=bing.com",
        "insecure": true,
        "alpn": [
          "h3"
        ]
      }
    },
    {
      "type": "direct",
      "tag": "direct"
    },
    {
      "type": "block",
      "tag": "block"
    },
    {
      "type": "dns",
      "tag": "dns-out"
    }
  ],
  "route": {
    "rules": [
      {
        "protocol": "dns",
        "outbound": "dns-out"
      },
      {
        "geosite": "category-ads-all",
        "outbound": "block"
      },
      {
        "geosite": "cn",
        "geoip": "cn",
        "outbound": "direct"
      }
    ],
    "auto_detect_interface": true
  }
}
```
4. 在OpenWrt的web界面中，进入网络-接口，添加一个新的接口，命名为vpn，选择协议为无（Unmanaged），覆盖物理设置为tun0，并应用设置。
5. 在OpenWrt的web界面中，进入网络-防火墙，编辑vpn接口所属的区域（默认为未分配），将其加入到lan区域，并应用设置。
6. 设置为init.d管理：
```
root@OpenWrt:~# cat /etc/init.d/sing-box
#!/bin/sh /etc/rc.common
#
# Copyright (C) 2022 by nekohasekai <contact-sagernet@sekai.icu>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#

START=99
USE_PROCD=1

#####  ONLY CHANGE THIS BLOCK  ######
PROG=/sing-box/sing-box # where is sing-box
RES_DIR=/sing-box/ # resource dir / working dir / the dir where you store ip/domain lists
CONF=/sing-box/config.json   # where is the config file, it can be a relative path to $RES_DIR
#####  ONLY CHANGE THIS BLOCK  ######

start_service() {
  procd_open_instance
  procd_set_param command $PROG run -D $RES_DIR -c $CONF

  procd_set_param user root
  procd_set_param limits core="unlimited"
  procd_set_param limits nofile="1000000 1000000"
  procd_set_param stdout 1
  procd_set_param stderr 1
  procd_set_param respawn "${respawn_threshold:-3600}" "${respawn_timeout:-5}" "${respawn_retry:-5}"
  procd_close_instance
  echo "sing-box is started!"
}

stop_service() {
  service_stop $PROG
  echo "sing-box is stopped!"
}

reload_service() {
  stop
  sleep 1s
  echo "sing-box is restarted!"
  start
}
```
- 有个问题，OpenWrt启动后这样直接自动启动sing-box会出问题，猜应该是wan口获得dhcp需要3、4秒，所以即使是开机自启99序的，sing-box的启动完成的时候，wan口还没有up，所以"auto_detect_interface"会推断不出wan口是哪个，完全上不去网。所以，再做个专门延迟启动sing-box的服务。
```
root@OpenWrt:~# cat /etc/init.d/delay_sing-box
#!/bin/sh /etc/rc.common

START=99

start() {
    sleep 9s
    /etc/init.d/sing-box start
}
```
- 再执行`/etc/init.d/delay_sing-box enable`,设置为开机自动启动。
# 以下是nft分流设置的具体过程。
6. 得到chn_ip.txt(将fakeip的地址段插入）：
```
#!/bin/bash

wget https://ftp.apnic.net/stats/apnic/delegated-apnic-latest; grep CN delegated-apnic-latest > delegated-cn-latest
awk -F'|' '/CN\|ipv4/ { printf("%s/%d\n", $4, 32-log($5)/log(2)) }' delegated-cn-latest > chn_ip.txt
sort -n -t . -k 1,1 -k 2,2 -k 3,3 -k 4,4 chn_ip.txt > chn_ip_sorted.txt
uniq chn_ip_sorted.txt > chn_ip_uniq.txt
echo "198.18.0.0/15" >> chn_ip_uniq.txt
aggregate -q < chn_ip_uniq.txt > chn_ip_final.txt

rm delegated-apnic-latest delegated-cn-latest chn_ip.txt chn_ip_sorted.txt chn_ip_uniq.txt
mv chn_ip_final.txt chn_ip.txt
```
7. 制作nft include的国内ip地址set，先每行加大括号

```
sed 's/^/{/;s/$/}/' ~/chn_ip.txt > ~/chn_ip.nft
```

- 然后制作成为如下格式（随便怎么弄，在windows里也可以）：

```
elements = {1.0.1.0/24,1.0.2.0/23,1.0.8.0/21,1.0.32.0/19, ... ,223.255.252.0/23}
```

8. 查看nftables中已有的表和链：
```
nft list tables
nft list chains
```
- 现在路由器的状态还是正常的未分流未启动tun0状态，是普通的路由器nft配置，保存这个配置以供复原用：
```
nft list ruleset > /sing-box/nft_novpn.conf
```
9. 创建一个新的表和链，先在shell里用以下的命令：
    - 在shell中，直接用分号会出问题，所以加上转义\）
```
nft add table ip filter
nft add chain ip filter china { type filter hook input priority 0\; policy accept\; }
```
- 然后在shell里执行 nftables 脚本
```
#!/usr/sbin/nft -f

# Create a table named filter in the ip family
table ip filter {
  # Create a set named china that contains the IP addresses from the file chn_ip.nft
  set china {
    type ipv4_addr
    flags interval
    include "~/chn_ip.nft"
  }

  # Create a chain named prerouting that hooks to the prerouting phase
  chain prerouting {
    type filter hook prerouting priority -150; policy accept;
    # If the destination address is in the china set, mark the packet with 1
    ip daddr @china mark set 1
  }

  # Create a chain named postrouting that hooks to the postrouting phase
  chain postrouting {
    type filter hook postrouting priority -150; policy accept;
    # If the source address is in the china set, mark the packet with 1
    ip saddr @china mark set 1
  }
}

# Create a table named route in the ip family
table ip route {
  # Create a chain named output that hooks to the output phase
  chain output {
    type route hook output priority -150; policy accept;
    # If the packet is marked with 1, route it to the original wan interface (replace eth1 with your actual interface name)
    mark 1 oifname "eth1" accept
    # Otherwise, route it to the vpn interface (replace tun0 with your actual interface name)
    oifname "tun0" accept
  }
}
```
- 这个脚本的基本思路是：
  - 在 filter 表中创建一个 china 集合，包含了所有分配给中国区的 IP 地址。
  - 在 filter 表中创建两个链，分别在 prerouting 和 postrouting 阶段，将目标地址或源地址在 china 集合中的数据包标记为 1。
  - 在 route 表中创建一个链，在 output 阶段，根据数据包的标记，将其路由到原来的 wan 接口或 vpn 接口。
- 将这个脚本保存为一个文件，比如 vpn_route.nft，然后在shell里执行它，
```
nft -f vpn_route.nft
```
10. 命令行直接手动启动sing-box，启用了fakeip，要等个几十秒起效，测试是否顺利。
```
/sing-box/sing-box run -c /sing-box/config.json
```
11. 顺利的话，将当下的nftables规则保存到一个文件中，供以后sing-box服务启动tun0（vpn）接口上联后自动加载：
```
nft list ruleset > /sing-box/nft_withvpn.conf
```
12. 设置vpn上联、下线的触发脚本
```
root@OpenWrt:~# cat /etc/hotplug.d/iface/99-vpnnft
#!/bin/bash

if [ $ACTION = ifup -a $INTERFACE = wan ]; then
    if ip link show tun0 > /dev/null 2>&1; then
            sh /etc/init.d/sing-box restart
    fi
fi

if [ "$INTERFACE" = "vpn" ]; then
      if [ "$ACTION" = "ifup" ]; then
          # vpn interface is up
          nft flush ruleset
          nft -f /sing-box/nft_withvpn.conf
      elif [ "$ACTION" = "ifdown" ]; then
          # vpn interface is down
          nft flush ruleset
          nft -f /sing-box/nft_novpn.conf
      fi
fi
```
- 这样就完成了分流的设置，目标地址不在china集合中的数据包走VPN链，并被转发到VPN网关，而其他数据包（国内ip）则走默认路由表。并完成了sing-box服务的自动启动配置。
- 都是临时抱佛脚搞通的，囫囵吞枣，不求甚解。非常希望有熟手来帮我指正。请随意发issue。
