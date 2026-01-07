"""
Security Monitoring - Anomaly Detection System
Detects unusual access patterns to patient records
"""

import pandas as pd
from datetime import datetime
import os

class SecurityMonitor:
    def __init__(self):
        self.user_baselines = {}
        self.alerts = []
    
    def load_baselines(self, csv_file):
        """Learn normal behavior from historical data"""
        print("Loading user baselines from historical data...")
        
        # Read historical logs
        df = pd.read_csv(csv_file)
        
        # Calculate baselines for each user
        for user in df['user'].unique():
            user_data = df[df['user'] == user]
            
            self.user_baselines[user] = {
                'avg_access': user_data['access_count'].mean(),
                'std_access': user_data['access_count'].std(),
                'max_access': user_data['access_count'].max(),
                'typical_hours': sorted(user_data['hour'].unique().tolist()),
                'typical_locations': user_data['location'].unique().tolist()
            }
        
        print(f"✓ Loaded baselines for {len(self.user_baselines)} users\n")
    
    def detect_anomaly(self, log_entry):
        """Check if current activity is anomalous"""
        user = log_entry['user']
        baseline = self.user_baselines.get(user)
        
        if not baseline:
            return None
        
        anomalies = []
        
        # Volume anomaly: access > 3 standard deviations above mean
        threshold = baseline['avg_access'] + (3 * baseline['std_access'])
        if log_entry['access_count'] > threshold:
            anomalies.append({
                'type': 'volume',
                'severity': 'HIGH',
                'details': f"Volume: {log_entry['access_count']} records (threshold: {threshold:.0f})"
            })
        
        # Time anomaly: outside typical hours
        if log_entry['hour'] not in baseline['typical_hours']:
            min_hour = min(baseline['typical_hours'])
            max_hour = max(baseline['typical_hours'])
            anomalies.append({
                'type': 'time',
                'severity': 'MEDIUM',
                'details': f"Off-hours: {log_entry['hour']}:00 (typical: {min_hour}:00-{max_hour}:00)"
            })
        
        # Location anomaly: unexpected geography
        if log_entry['location'] not in baseline['typical_locations']:
            expected = ', '.join(baseline['typical_locations'])
            anomalies.append({
                'type': 'location',
                'severity': 'HIGH',
                'details': f"Location: {log_entry['location']} (expected: {expected})"
            })
        
        return anomalies if anomalies else None
    
    def parse_log_line(self, line):
        """Parse a log entry into structured data"""
        parts = line.strip().split('|')
        return {
            'timestamp': parts[0].strip(),
            'user': parts[1].strip(),
            'access_count': int(parts[2].strip()),
            'hour': int(parts[3].strip()),
            'location': parts[4].strip(),
            'ip_address': parts[5].strip()
        }
    
    def process_logs(self, log_file):
        """Process log file and detect anomalies"""
        print("Processing access logs...")
        
        with open(log_file, 'r') as f:
            # Skip header
            next(f)
            
            for line in f:
                if line.strip():
                    log_entry = self.parse_log_line(line)
                    anomalies = self.detect_anomaly(log_entry)
                    
                    if anomalies:
                        self.trigger_alert(log_entry, anomalies)
    
    def trigger_alert(self, log_entry, anomalies):
        """Generate security alert"""
        # Determine severity
        severity_levels = [a['severity'] for a in anomalies]
        severity = 'HIGH' if 'HIGH' in severity_levels else 'MEDIUM'
        
        alert = {
            'timestamp': log_entry['timestamp'],
            'user': log_entry['user'],
            'severity': severity,
            'anomalies': anomalies,
            'log_entry': log_entry
        }
        
        self.alerts.append(alert)
        
        # Print alert to console
        print("---")
        print(f"[ALERT] {severity} SEVERITY - User: {log_entry['user']}")
        print(f"  Time: {log_entry['timestamp']}")
        print(f"  Anomalies:")
        for anomaly in anomalies:
            print(f"    - {anomaly['details']}")
        print("---\n")
    
    def generate_report(self):
        """Generate summary report"""
        print("=" * 60)
        print("SECURITY MONITORING REPORT")
        print("=" * 60)
        print(f"Total Alerts: {len(self.alerts)}")
        
        high_severity = [a for a in self.alerts if a['severity'] == 'HIGH']
        medium_severity = [a for a in self.alerts if a['severity'] == 'MEDIUM']
        
        print(f"  - HIGH Severity: {len(high_severity)}")
        print(f"  - MEDIUM Severity: {len(medium_severity)}")
        
        if self.alerts:
            print("\nTop Concerns:")
            for alert in self.alerts[:5]:  # Show first 5
                print(f"  • {alert['user']} - {alert['severity']} - {alert['timestamp']}")
        
        print("=" * 60)


def main():
    """Main execution function"""
    print("\n=== Security Monitoring System ===\n")
    
    # Initialize monitor
    monitor = SecurityMonitor()
    
    # File paths
    historical_data = 'data/historical_access_logs.csv'
    current_logs = 'data/current_access_log.txt'
    
    # Check if files exist
    if not os.path.exists(historical_data):
        print(f"ERROR: {historical_data} not found!")
        print("Please run: python scripts/generate_test_data.py")
        return
    
    if not os.path.exists(current_logs):
        print(f"ERROR: {current_logs} not found!")
        print("Please run: python scripts/generate_test_data.py")
        return
    
    # Load baselines from historical data
    monitor.load_baselines(historical_data)
    
    # Process current logs
    monitor.process_logs(current_logs)
    
    # Generate report
    print(f"\nTotal logs processed: {sum(1 for _ in open(current_logs)) - 1}")
    print(f"Total alerts generated: {len(monitor.alerts)}\n")
    
    if monitor.alerts:
        monitor.generate_report()
    else:
        print("✓ No anomalies detected - all activity within normal parameters")


if __name__ == "__main__":
    main()