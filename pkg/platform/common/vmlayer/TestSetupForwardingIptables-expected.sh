#!/bin/bash
set -e
ip netns add iptablestestns
ip netns exec iptablestestns iptables-save
ip netns exec iptablestestns iptables -t nat -A POSTROUTING -o ens3 -j MASQUERADE
ip netns exec iptablestestns iptables -A FORWARD -i ens3 -o ens4 -m state --state RELATED,ESTABLISHED -j ACCEPT
ip netns exec iptablestestns iptables -A FORWARD -i ens4 -o ens3 -j ACCEPT
# bash -c 'iptables-save > /etc/iptables/rules.v4'
ip netns exec iptablestestns ip6tables-save
ip netns exec iptablestestns ip6tables -t nat -A POSTROUTING -o ens3 -j MASQUERADE
ip netns exec iptablestestns ip6tables -A FORWARD -i ens3 -o ens4 -m state --state RELATED,ESTABLISHED -j ACCEPT
ip netns exec iptablestestns ip6tables -A FORWARD -i ens4 -o ens3 -j ACCEPT
# bash -c 'ip6tables-save > /etc/iptables/rules.v6'
ip netns delete iptablestestns
