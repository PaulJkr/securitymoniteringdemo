"""
Security Monitoring - Brute Force Attack Detection
Detects credential stuffing and brute force login attempts
"""

from collections import defaultdict
from datetime import datetime, timedelta
import os

class BruteForceDetector:
    def __init__(self, threshold=5, time_window=300):
        """
        Initialize brute force detector
        
        Args:
            threshold: Number of failed attempts to trigger alert (default: 5)
            time_window: Time period in seconds (default: 300 = 5 minutes)
        """
        self.threshold = threshold
        self.time_window = time_window
        self.failed_attempts = defaultdict(list)
        self.blocked_ips = set()
        self.alerts = []
    
    def parse_log_line(self, line):
        """Parse authentication log entry"""
        parts = line.strip().split('|')
        return {
            'timestamp': datetime.strptime(parts[0].strip(), '%Y-%m-%d %H:%M:%S'),
            'user': parts[1].strip(),
            'ip_address': parts[2].strip(),
            'status': parts[3].strip(),
            'location': parts[4].strip()
        }
    
    def process_login_attempt(self, log_entry):
        """Process each login attempt and detect brute force"""
        ip_address = log_entry['ip_address']
        user = log_entry['user']
        status = log_entry['status']
        timestamp = log_entry['timestamp']
        
        # Skip already blocked IPs
        if ip_address in self.blocked_ips:
            return
        
        if status == 'FAILED':
            # Record failed attempt
            key = f"{ip_address}:{user}"
            self.failed_attempts[key].append({
                'timestamp': timestamp,
                'location': log_entry['location']
            })
            
            # Clean old attempts outside time window
            cutoff = timestamp - timedelta(seconds=self.time_window)
            self.failed_attempts[key] = [
                attempt for attempt in self.failed_attempts[key]
                if attempt['timestamp'] > cutoff
            ]
            
            # Check if threshold exceeded
            attempt_count = len(self.failed_attempts[key])
            if attempt_count >= self.threshold:
                self.trigger_brute_force_alert(
                    ip_address, 
                    user, 
                    attempt_count,
                    log_entry['location']
                )
    
    def trigger_brute_force_alert(self, ip, user, attempt_count, location):
        """Handle detected brute force attack"""
        # Only alert once per IP
        if ip in self.blocked_ips:
            return
        
        alert = {
            'timestamp': datetime.now(),
            'ip_address': ip,
            'target_user': user,
            'attempt_count': attempt_count,
            'location': location,
            'severity': 'CRITICAL'
        }
        
        self.alerts.append(alert)
        
        # Print alert
        print("\n" + "=" * 70)
        print("[CRITICAL] BRUTE FORCE ATTACK DETECTED!")
        print("=" * 70)
        print(f"  IP Address: {ip}")
        print(f"  Target User: {user}")
        print(f"  Failed Attempts: {attempt_count}")
        print(f"  Location: {location}")
        print(f"  Time Window: {self.time_window // 60} minutes")
        print("\n  Actions Taken:")
        
        # Block IP
        self.block_ip(ip)
        print(f"  ✓ IP address blocked")
        
        # Force password reset
        self.force_password_reset(user)
        print(f"  ✓ Password reset required for {user}")
        
        # Alert security team
        self.send_critical_alert(alert)
        print(f"  ✓ Security team notified")
        
        print("=" * 70 + "\n")
    
    def block_ip(self, ip_address):
        """Add IP to blocklist"""
        self.blocked_ips.add(ip_address)
        # In production: Call firewall API
        # firewall.add_block_rule(ip_address)
    
    def force_password_reset(self, user):
        """Require immediate password change"""
        # In production: Call user management API
        # user_api.require_password_reset(user)
        # user_api.send_security_notification(user)
        pass
    
    def send_critical_alert(self, alert):
        """Notify security team immediately"""
        # In production: Send via multiple channels
        # - Email to security@nexahealth.com
        # - SMS to on-call engineer
        # - Slack/Teams notification
        # - SIEM alert
        pass
    
    def process_log_file(self, log_file):
        """Process entire authentication log file"""
        print("Processing login attempts...")
        
        with open(log_file, 'r') as f:
            # Skip header
            next(f)
            
            for line in f:
                if line.strip():
                    log_entry = self.parse_log_line(line)
                    self.process_login_attempt(log_entry)
    
    def generate_report(self):
        """Generate detection summary report"""
        print("\n" + "=" * 70)
        print("BRUTE FORCE DETECTION REPORT")
        print("=" * 70)
        print(f"Detection Threshold: {self.threshold} failed attempts")
        print(f"Time Window: {self.time_window // 60} minutes")
        print(f"\nResults:")
        print(f"  Attacks Detected: {len(self.alerts)}")
        print(f"  IP Addresses Blocked: {len(self.blocked_ips)}")
        
        if self.alerts:
            print(f"\nDetected Attacks:")
            for i, alert in enumerate(self.alerts, 1):
                print(f"\n  Attack #{i}:")
                print(f"    IP: {alert['ip_address']}")
                print(f"    Target: {alert['target_user']}")
                print(f"    Attempts: {alert['attempt_count']}")
                print(f"    Location: {alert['location']}")
        
        print("\n" + "=" * 70)


def main():
    """Main execution function"""
    print("\n=== Brute Force Detection System ===\n")
    
    # Initialize detector
    detector = BruteForceDetector(threshold=5, time_window=300)
    
    # File path
    auth_log = 'data/auth_log.txt'
    
    # Check if file exists
    if not os.path.exists(auth_log):
        print(f"ERROR: {auth_log} not found!")
        print("Please run: python scripts/generate_test_data.py")
        return
    
    # Process logs
    detector.process_log_file(auth_log)
    
    # Generate report
    total_attempts = sum(1 for _ in open(auth_log)) - 1
    print(f"\nTotal attempts processed: {total_attempts}")
    
    if detector.alerts:
        detector.generate_report()
    else:
        print("✓ No brute force attacks detected\n")


if __name__ == "__main__":
    main()