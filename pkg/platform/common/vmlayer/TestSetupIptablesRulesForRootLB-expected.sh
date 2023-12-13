#!/bin/bash
set -e
ip netns add iptablestestns
ip netns exec iptablestestns iptables-save
ip netns exec iptablestestns ip6tables-save
ip netns exec iptablestestns iptables -I OUTPUT -d 10.201.0.0/16 -m comment --comment "label rootlb-networking" -j ACCEPT
ip netns exec iptablestestns iptables -I FORWARD -d 10.201.0.0/16 -m comment --comment "label rootlb-networking" -j ACCEPT
ip netns exec iptablestestns ip6tables -I OUTPUT -d fc00:201:ecec:0::/64 -m comment --comment "label rootlb-networking" -j ACCEPT
ip netns exec iptablestestns ip6tables -I FORWARD -d fc00:201:ecec:0::/64 -m comment --comment "label rootlb-networking" -j ACCEPT
ip netns exec iptablestestns iptables -I INPUT -p tcp -m tcp --dport 22 -m comment --comment "label rootlb-networking" -j ACCEPT
ip netns exec iptablestestns ip6tables -I INPUT -p tcp -m tcp --dport 22 -m comment --comment "label rootlb-networking" -j ACCEPT
ip netns exec iptablestestns iptables -I INPUT -s 10.201.0.0/16 -m comment --comment "label rootlb-networking" -j ACCEPT
ip netns exec iptablestestns ip6tables -I INPUT -s fc00:201:ecec:0::/64 -m comment --comment "label rootlb-networking" -j ACCEPT
# bash -c 'iptables-save > /etc/iptables/rules.v4'
# bash -c 'ip6tables-save > /etc/iptables/rules.v6'
ip netns exec iptablestestns iptables-save
ip netns exec iptablestestns ip6tables-save
ip netns exec iptablestestns iptables-save
ip netns exec iptablestestns ip6tables-save
ip netns exec iptablestestns iptables-save
ip netns exec iptablestestns ip6tables-save
ip netns exec iptablestestns iptables -I OUTPUT -m comment --comment "label sec-group" -j ACCEPT
ip netns exec iptablestestns iptables -I FORWARD -m comment --comment "label sec-group" -j ACCEPT
ip netns exec iptablestestns ip6tables -I OUTPUT -m comment --comment "label sec-group" -j ACCEPT
ip netns exec iptablestestns ip6tables -I FORWARD -m comment --comment "label sec-group" -j ACCEPT
# bash -c 'iptables-save > /etc/iptables/rules.v4'
# bash -c 'ip6tables-save > /etc/iptables/rules.v6'
ip netns exec iptablestestns iptables-save
ip netns exec iptablestestns ip6tables-save
ip netns exec iptablestestns iptables -I OUTPUT -o lo -m comment --comment "label default-rules" -j ACCEPT
ip netns exec iptablestestns iptables -I FORWARD -o lo -m comment --comment "label default-rules" -j ACCEPT
ip netns exec iptablestestns iptables -I OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment "label default-rules" -j ACCEPT
ip netns exec iptablestestns iptables -I FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment "label default-rules" -j ACCEPT
ip netns exec iptablestestns iptables -I INPUT -i lo -m comment --comment "label default-rules" -j ACCEPT
ip netns exec iptablestestns iptables -I INPUT -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment "label default-rules" -j ACCEPT
# bash -c 'iptables-save > /etc/iptables/rules.v4'
ip netns exec iptablestestns iptables -P INPUT DROP
ip netns exec iptablestestns iptables -P OUTPUT DROP
ip netns exec iptablestestns iptables-save
ip netns exec iptablestestns ip6tables-save
ip netns exec iptablestestns ip6tables -I OUTPUT -o lo -m comment --comment "label default-rules" -j ACCEPT
ip netns exec iptablestestns ip6tables -I FORWARD -o lo -m comment --comment "label default-rules" -j ACCEPT
ip netns exec iptablestestns ip6tables -I OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment "label default-rules" -j ACCEPT
ip netns exec iptablestestns ip6tables -I FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment "label default-rules" -j ACCEPT
ip netns exec iptablestestns ip6tables -I INPUT -i lo -m comment --comment "label default-rules" -j ACCEPT
ip netns exec iptablestestns ip6tables -I INPUT -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment "label default-rules" -j ACCEPT
# bash -c 'ip6tables-save > /etc/iptables/rules.v6'
ip netns exec iptablestestns ip6tables -P INPUT DROP
ip netns exec iptablestestns ip6tables -P OUTPUT DROP
ip netns delete iptablestestns
