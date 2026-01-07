"""
Test Data Generator for Security Monitoring Demo
Generates realistic access logs and authentication logs
"""

import random
import csv
from datetime import datetime, timedelta

# User profiles with typical behavior patterns
USER_PROFILES = {
    'dr_kamau': {
        'avg_access': 25,
        'std': 5,
        'hours': [8, 9, 10, 11, 14, 15, 16, 17],
        'location': 'Nairobi, KE'
    },
    'nurse_wanjiru': {
        'avg_access': 15,
        'std': 3,
        'hours': [7, 8, 9, 10, 11, 12, 13, 14],
        'location': 'Nairobi, KE'
    },
    'receptionist_otieno': {
        'avg_access': 12,
        'std': 2,
        'hours': [8, 9, 10, 11, 12, 13, 14, 15, 16],
        'location': 'Nairobi, KE'
    },
    'admin_kimani': {
        'avg_access': 8,
        'std': 2,
        'hours': [9, 10, 11, 12, 13, 14, 15, 16, 17],
        'location': 'Nairobi, KE'
    }
}

# IP address pools
NAIROBI_IPS = ['197.156.{}.{}'.format(random.randint(1, 255), random.randint(1, 255)) for _ in range(20)]
FOREIGN_IPS = [
    '41.203.12.45',  # Lagos, Nigeria
    '195.88.54.23',  # Moscow, Russia
    '185.220.101.45',  # TOR Exit Node
    '103.21.58.67'   # Mumbai, India
]


def generate_historical_logs(num_records=1000):
    """Generate historical access logs (normal behavior)"""
    print("Generating historical access logs...")
    
    records = []
    start_date = datetime.now() - timedelta(days=30)
    
    for _ in range(num_records):
        user = random.choice(list(USER_PROFILES.keys()))
        profile = USER_PROFILES[user]
        
        # Generate normal behavior
        access_count = int(random.gauss(profile['avg_access'], profile['std']))
        access_count = max(1, access_count)  # Ensure positive
        
        hour = random.choice(profile['hours'])
        location = profile['location']
        ip_address = random.choice(NAIROBI_IPS)
        
        # Random timestamp within last 30 days
        timestamp = start_date + timedelta(
            days=random.randint(0, 29),
            hours=hour,
            minutes=random.randint(0, 59)
        )
        
        records.append({
            'timestamp': timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'user': user,
            'access_count': access_count,
            'hour': hour,
            'location': location,
            'ip_address': ip_address
        })
    
    # Write to CSV
    with open('data/historical_access_logs.csv', 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=['timestamp', 'user', 'access_count', 'hour', 'location', 'ip_address'])
        writer.writeheader()
        writer.writerows(records)
    
    print(f"✓ Generated historical_access_logs.csv ({num_records} records)")


def generate_current_logs(num_normal=40, num_anomalous=10):
    """Generate current access logs with anomalies"""
    print("Generating current access logs with anomalies...")
    
    records = []
    
    # Generate normal records
    for _ in range(num_normal):
        user = random.choice(list(USER_PROFILES.keys()))
        profile = USER_PROFILES[user]
        
        access_count = int(random.gauss(profile['avg_access'], profile['std']))
        access_count = max(1, access_count)
        
        hour = random.choice(profile['hours'])
        location = profile['location']
        ip_address = random.choice(NAIROBI_IPS)
        
        timestamp = datetime.now() - timedelta(hours=random.randint(0, 24))
        
        records.append({
            'timestamp': timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'user': user,
            'access_count': access_count,
            'hour': hour,
            'location': location,
            'ip_address': ip_address
        })
    
    # Generate anomalous records
    anomaly_scenarios = [
        {
            'user': 'receptionist_otieno',
            'access_count': random.randint(400, 500),
            'hour': 2,
            'location': 'Lagos, NG',
            'ip_address': FOREIGN_IPS[0]
        },
        {
            'user': 'nurse_wanjiru',
            'access_count': random.randint(150, 200),
            'hour': 23,
            'location': 'Nairobi, KE',
            'ip_address': random.choice(NAIROBI_IPS)
        },
        {
            'user': 'dr_kamau',
            'access_count': 28,
            'hour': 3,
            'location': 'Moscow, RU',
            'ip_address': FOREIGN_IPS[1]
        },
    ]
    
    for _ in range(num_anomalous):
        scenario = random.choice(anomaly_scenarios)
        timestamp = datetime.now() - timedelta(hours=random.randint(0, 24))
        
        records.append({
            'timestamp': timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'user': scenario['user'],
            'access_count': scenario['access_count'],
            'hour': scenario['hour'],
            'location': scenario['location'],
            'ip_address': scenario['ip_address']
        })
    
    # Shuffle records
    random.shuffle(records)
    
    # Write to text file (log format)
    with open('data/current_access_log.txt', 'w') as f:
        f.write("timestamp | user | access_count | hour | location | ip_address\n")
        for record in records:
            f.write(f"{record['timestamp']} | {record['user']} | {record['access_count']} | {record['hour']} | {record['location']} | {record['ip_address']}\n")
    
    print(f"✓ Generated current_access_log.txt ({len(records)} records)")


def generate_auth_logs(num_normal=80, num_attacks=20):
    """Generate authentication logs with brute force attacks"""
    print("Generating authentication logs with attacks...")
    
    records = []
    
    # Generate normal login attempts
    for _ in range(num_normal):
        user = random.choice(list(USER_PROFILES.keys()))
        status = random.choice(['SUCCESS', 'SUCCESS', 'SUCCESS', 'FAILED'])  # 75% success
        ip_address = random.choice(NAIROBI_IPS)
        location = 'Nairobi, KE'
        
        timestamp = datetime.now() - timedelta(hours=random.randint(0, 48))
        
        records.append({
            'timestamp': timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'user': user,
            'ip_address': ip_address,
            'status': status,
            'location': location
        })
    
    # Generate brute force attacks
    attack_scenarios = [
        {
            'target_user': 'admin_kimani',
            'attacker_ip': FOREIGN_IPS[2],
            'location': 'Unknown (TOR Exit Node)',
            'attempts': 12
        },
        {
            'target_user': 'dr_kamau',
            'attacker_ip': FOREIGN_IPS[3],
            'location': 'Mumbai, IN',
            'attempts': 8
        }
    ]
    
    for scenario in attack_scenarios:
        base_time = datetime.now() - timedelta(hours=random.randint(1, 24))
        
        for i in range(scenario['attempts']):
            timestamp = base_time + timedelta(seconds=i * 15)  # 15 seconds apart
            
            records.append({
                'timestamp': timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                'user': scenario['target_user'],
                'ip_address': scenario['attacker_ip'],
                'status': 'FAILED',
                'location': scenario['location']
            })
    
    # Sort by timestamp
    records.sort(key=lambda x: x['timestamp'])
    
    # Write to text file
    with open('data/auth_log.txt', 'w') as f:
        f.write("timestamp | user | ip_address | status | location\n")
        for record in records:
            f.write(f"{record['timestamp']} | {record['user']} | {record['ip_address']} | {record['status']} | {record['location']}\n")
    
    print(f"✓ Generated auth_log.txt ({len(records)} records)")


def main():
    """Generate all test data files"""
    print("\n=== Test Data Generator ===\n")
    
    # Create data directory if it doesn't exist
    import os
    os.makedirs('data', exist_ok=True)
    
    # Generate all datasets
    generate_historical_logs(1000)
    generate_current_logs(40, 10)
    generate_auth_logs(80, 20)
    
    print("\n✓ All test data generated successfully!")
    print("\nData files created in ./data/ directory:")
    print("  - historical_access_logs.csv (baseline data)")
    print("  - current_access_log.txt (logs to analyze)")
    print("  - auth_log.txt (login attempts)")
    print("\nNext steps:")
    print("  1. Run: python scripts/anomaly_detector.py")
    print("  2. Run: python scripts/brute_force_detector.py")
    print()


if __name__ == "__main__":
    main()