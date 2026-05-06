import subprocess
import logging
import os

class RawMitigator:
    def __init__(self, whitelist_str):
        self.whitelist = {ip.strip() for ip in whitelist_str.split(",")}
        self.blocked_ips = set()
        self._init_firewall()

    def _init_firewall(self):
        try:
            subprocess.run(["iptables", "-t", "raw", "-F"], check=True)
            subprocess.run([
                "iptables", "-t", "raw", "-A", "PREROUTING", 
                "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"
            ], check=True)
            logging.info("IPS Defensive layers initialized.")
        except Exception as e:
            logging.error(f"Firewall init failed: {e}")

    def block(self, ip):
        if ip in self.whitelist or ip in self.blocked_ips:
            return False

        try:
            subprocess.run([
                "iptables", "-t", "raw", "-I", "PREROUTING", "1", 
                "-s", ip, "-j", "DROP"
            ], check=True)
            self.blocked_ips.add(ip)
            logging.warning(f"!!! BAN APPLIED: {ip} is now dropped at RAW level !!!")
            return True
        except Exception as e:
            logging.error(f"Failed to ban {ip}: {e}")
            return False