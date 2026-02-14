"""
GUI Attack Simulator for IDS-ML System
Automatically sends attacks and displays results on the dashboard
No terminal output - everything happens on the web dashboard
"""

import requests
import time
import random
from datetime import datetime
import webbrowser
import json

# API Configuration
API_URL = 'http://localhost:8000'
DASHBOARD_URL = 'http://localhost:3000'

# Attack patterns
ATTACK_PATTERNS = {
    'neptune': {
        'name': 'Neptune DoS Attack',
        'description': 'SYN flood attack overwhelming the server',
        'features': {
            'protocol_type': 'tcp',
            'service': 'private',
            'flag': 'S0',
            'src_bytes': lambda: random.randint(0, 10),
            'dst_bytes': lambda: random.randint(0, 10),
            'duration': lambda: 0,
            'logged_in': lambda: 0,
            'count': lambda: random.randint(400, 511),
            'srv_count': lambda: random.randint(400, 511),
            'serror_rate': lambda: round(random.uniform(0.9, 1.0), 2),
            'srv_serror_rate': lambda: round(random.uniform(0.9, 1.0), 2),
            'dst_host_srv_count': lambda: random.randint(200, 255)
        }
    },

    'smurf': {
        'name': 'Smurf DoS Attack',
        'description': 'ICMP broadcast flood attack',
        'features': {
            'protocol_type': 'icmp',
            'service': 'ecr_i',
            'flag': 'SF',
            'src_bytes': lambda: random.randint(1000, 1500),
            'dst_bytes': lambda: 0,
            'duration': lambda: 0,
            'logged_in': lambda: 0,
            'count': lambda: random.randint(450, 511),
            'srv_count': lambda: random.randint(450, 511),
            'serror_rate': lambda: 0.0,
            'srv_serror_rate': lambda: 0.0,
            'dst_host_srv_count': lambda: random.randint(220, 255)
        }
    },

    'portsweep': {
        'name': 'Port Sweep Attack',
        'description': 'Scanning multiple ports for vulnerabilities',
        'features': {
            'protocol_type': 'tcp',
            'service': 'private',
            'flag': 'REJ',
            'src_bytes': lambda: random.randint(0, 50),
            'dst_bytes': lambda: random.randint(0, 50),
            'duration': lambda: random.randint(0, 3),
            'logged_in': lambda: 0,
            'count': lambda: random.randint(250, 400),
            'srv_count': lambda: random.randint(25, 50),
            'serror_rate': lambda: round(random.uniform(0.7, 1.0), 2),
            'srv_serror_rate': lambda: round(random.uniform(0.7, 1.0), 2),
            'dst_host_srv_count': lambda: random.randint(80, 150)
        }
    },

    'satan': {
        'name': 'Satan Probe Attack',
        'description': 'Security vulnerability scanner',
        'features': {
            'protocol_type': 'tcp',
            'service': 'http',
            'flag': 'SF',
            'src_bytes': lambda: random.randint(150, 400),
            'dst_bytes': lambda: random.randint(6000, 10000),
            'duration': lambda: random.randint(0, 8),
            'logged_in': lambda: 0,
            'count': lambda: random.randint(1, 5),
            'srv_count': lambda: random.randint(1, 5),
            'serror_rate': lambda: 0.0,
            'srv_serror_rate': lambda: 0.0,
            'dst_host_srv_count': lambda: random.randint(25, 50)
        }
    },

    'ipsweep': {
        'name': 'IP Sweep Attack',
        'description': 'Ping scanning IP address range',
        'features': {
            'protocol_type': 'icmp',
            'service': 'eco_i',
            'flag': 'SF',
            'src_bytes': lambda: 8,
            'dst_bytes': lambda: 0,
            'duration': lambda: 0,
            'logged_in': lambda: 0,
            'count': lambda: random.randint(1, 8),
            'srv_count': lambda: random.randint(1, 8),
            'serror_rate': lambda: 0.0,
            'srv_serror_rate': lambda: 0.0,
            'dst_host_srv_count': lambda: random.randint(120, 255)
        }
    },

    'back': {
        'name': 'Back DoS Attack',
        'description': 'Apache web server exploit',
        'features': {
            'protocol_type': 'tcp',
            'service': 'http',
            'flag': 'SF',
            'src_bytes': lambda: random.randint(350, 550),
            'dst_bytes': lambda: random.randint(12000, 18000),
            'duration': lambda: random.randint(8, 25),
            'logged_in': lambda: 1,
            'count': lambda: random.randint(70, 140),
            'srv_count': lambda: random.randint(70, 140),
            'serror_rate': lambda: 0.0,
            'srv_serror_rate': lambda: 0.0,
            'dst_host_srv_count': lambda: random.randint(15, 45)
        }
    },

    'teardrop': {
        'name': 'Teardrop DoS Attack',
        'description': 'IP fragmentation attack',
        'features': {
            'protocol_type': 'udp',
            'service': 'private',
            'flag': 'SF',
            'src_bytes': lambda: random.randint(0, 40),
            'dst_bytes': lambda: random.randint(0, 40),
            'duration': lambda: 0,
            'logged_in': lambda: 0,
            'count': lambda: random.randint(1, 8),
            'srv_count': lambda: random.randint(1, 8),
            'serror_rate': lambda: 0.0,
            'srv_serror_rate': lambda: 0.0,
            'dst_host_srv_count': lambda: random.randint(1, 8)
        }
    },

    'pod': {
        'name': 'Ping of Death',
        'description': 'Oversized ICMP packet attack',
        'features': {
            'protocol_type': 'icmp',
            'service': 'eco_i',
            'flag': 'SF',
            'src_bytes': lambda: random.randint(66000, 68000),
            'dst_bytes': lambda: 0,
            'duration': lambda: 0,
            'logged_in': lambda: 0,
            'count': lambda: random.randint(1, 4),
            'srv_count': lambda: random.randint(1, 4),
            'serror_rate': lambda: 0.0,
            'srv_serror_rate': lambda: 0.0,
            'dst_host_srv_count': lambda: random.randint(1, 8)
        }
    }
}

NORMAL_PATTERNS = {
    'http_normal': {
        'name': 'Normal HTTP Traffic',
        'description': 'Legitimate web browsing',
        'features': {
            'protocol_type': 'tcp',
            'service': 'http',
            'flag': 'SF',
            'src_bytes': lambda: random.randint(120, 450),
            'dst_bytes': lambda: random.randint(2000, 9000),
            'duration': lambda: random.randint(0, 45),
            'logged_in': lambda: random.choice([0, 1]),
            'count': lambda: random.randint(1, 18),
            'srv_count': lambda: random.randint(1, 18),
            'serror_rate': lambda: 0.0,
            'srv_serror_rate': lambda: 0.0,
            'dst_host_srv_count': lambda: random.randint(1, 28)
        }
    },

    'ftp_normal': {
        'name': 'Normal FTP Transfer',
        'description': 'File transfer protocol',
        'features': {
            'protocol_type': 'tcp',
            'service': 'ftp',
            'flag': 'SF',
            'src_bytes': lambda: random.randint(60, 180),
            'dst_bytes': lambda: random.randint(800, 4500),
            'duration': lambda: random.randint(0, 250),
            'logged_in': lambda: 1,
            'count': lambda: random.randint(1, 9),
            'srv_count': lambda: random.randint(1, 9),
            'serror_rate': lambda: 0.0,
            'srv_serror_rate': lambda: 0.0,
            'dst_host_srv_count': lambda: random.randint(1, 14)
        }
    },

    'smtp_normal': {
        'name': 'Normal Email Traffic',
        'description': 'SMTP mail transfer',
        'features': {
            'protocol_type': 'tcp',
            'service': 'smtp',
            'flag': 'SF',
            'src_bytes': lambda: random.randint(250, 900),
            'dst_bytes': lambda: random.randint(250, 900),
            'duration': lambda: random.randint(0, 100),
            'logged_in': lambda: 1,
            'count': lambda: random.randint(1, 4),
            'srv_count': lambda: random.randint(1, 4),
            'serror_rate': lambda: 0.0,
            'srv_serror_rate': lambda: 0.0,
            'dst_host_srv_count': lambda: random.randint(1, 9)
        }
    },

    'ssh_normal': {
        'name': 'Normal SSH Session',
        'description': 'Secure shell connection',
        'features': {
            'protocol_type': 'tcp',
            'service': 'ssh',
            'flag': 'SF',
            'src_bytes': lambda: random.randint(1500, 4500),
            'dst_bytes': lambda: random.randint(1500, 4500),
            'duration': lambda: random.randint(80, 500),
            'logged_in': lambda: 1,
            'count': lambda: random.randint(1, 2),
            'srv_count': lambda: random.randint(1, 2),
            'serror_rate': lambda: 0.0,
            'srv_serror_rate': lambda: 0.0,
            'dst_host_srv_count': lambda: random.randint(1, 4)
        }
    }
}


class DashboardSimulator:
    """Sends attacks directly to dashboard"""

    def __init__(self):
        self.attack_count = 0
        self.normal_count = 0
        self.total_count = 0

    def generate_features(self, pattern):
        """Generate features from pattern"""
        features = {}
        for key, value in pattern['features'].items():
            if callable(value):
                features[key] = value()
            else:
                features[key] = value
        return features

    def send_to_api(self, features, traffic_type, pattern_name):
        """Send traffic to API"""
        try:
            response = requests.post(
                f'{API_URL}/predict',
                json=features,
                timeout=5
            )

            if response.status_code == 200:
                result = response.json()
                self.total_count += 1

                # Print minimal info to console
                icon = "🔴" if result['is_attack'] else "🟢"
                print(f"{icon} Sent: {pattern_name} → Dashboard updated")

                return result
            else:
                print(f"❌ API Error: {response.status_code}")
                return None

        except Exception as e:
            print(f"❌ Connection Error: {e}")
            print("Make sure backend is running on http://localhost:8000")
            return None

    def simulate_attack(self, attack_type=None):
        """Send an attack"""
        if attack_type is None:
            attack_type = random.choice(list(ATTACK_PATTERNS.keys()))

        pattern = ATTACK_PATTERNS[attack_type]
        features = self.generate_features(pattern)

        self.attack_count += 1
        return self.send_to_api(features, 'ATTACK', pattern['name'])

    def simulate_normal(self, traffic_type=None):
        """Send normal traffic"""
        if traffic_type is None:
            traffic_type = random.choice(list(NORMAL_PATTERNS.keys()))

        pattern = NORMAL_PATTERNS[traffic_type]
        features = self.generate_features(pattern)

        self.normal_count += 1
        return self.send_to_api(features, 'NORMAL', pattern['name'])

    def run_demo(self, num_packets=30, attack_probability=0.4, delay=2.0):
        """Run simulation visible on dashboard"""

        print("\n" + "="*70)
        print("🚀 IDS-ML DASHBOARD ATTACK SIMULATOR")
        print("="*70)
        print(f"\n📊 Configuration:")
        print(f"   Total Packets: {num_packets}")
        print(f"   Attack Rate: {attack_probability*100:.0f}%")
        print(f"   Delay: {delay} seconds between packets")
        print(f"\n🌐 Dashboard: {DASHBOARD_URL}")
        print(f"\n⏳ Starting in 3 seconds...")
        print("   Watch your browser dashboard for real-time updates!")
        print("="*70)

        # Open dashboard if not already open
        time.sleep(1)
        try:
            webbrowser.open(DASHBOARD_URL)
        except:
            pass

        time.sleep(2)

        print(f"\n🎬 Simulation Started!\n")

        for i in range(num_packets):
            print(f"[{i+1}/{num_packets}] ", end="")

            if random.random() < attack_probability:
                self.simulate_attack()
            else:
                self.simulate_normal()

            if i < num_packets - 1:
                time.sleep(delay)

        # Summary
        print(f"\n\n" + "="*70)
        print("✅ SIMULATION COMPLETE!")
        print("="*70)
        print(f"\n📊 Results (check dashboard for details):")
        print(f"   Total Sent: {self.total_count}")
        print(f"   ├─ Normal Traffic: {self.normal_count}")
        print(f"   └─ Attack Traffic: {self.attack_count}")
        print(f"\n👀 View detailed results on your dashboard:")
        print(f"   {DASHBOARD_URL}")
        print("="*70)

    def demonstrate_all_attacks(self):
        """Show one of each attack type"""

        print("\n" + "="*70)
        print("🎯 DEMONSTRATING ALL ATTACK TYPES")
        print("="*70)
        print(f"\n🌐 Dashboard: {DASHBOARD_URL}")
        print("\n⏳ Starting in 3 seconds...")
        print("   Watch the dashboard update with each attack!")
        print("="*70)

        time.sleep(1)
        try:
            webbrowser.open(DASHBOARD_URL)
        except:
            pass

        time.sleep(2)

        print(f"\n🎬 Demonstrating Attacks...\n")

        # Show all attacks
        for attack_type, pattern in ATTACK_PATTERNS.items():
            print(f"\n🔴 Testing: {pattern['name']}")
            print(f"   Description: {pattern['description']}")
            self.simulate_attack(attack_type)
            time.sleep(2)

        # Show normal traffic examples
        print(f"\n\n🟢 Testing Normal Traffic...\n")
        for normal_type, pattern in NORMAL_PATTERNS.items():
            print(f"\n🟢 Testing: {pattern['name']}")
            print(f"   Description: {pattern['description']}")
            self.simulate_normal(normal_type)
            time.sleep(2)

        print(f"\n\n" + "="*70)
        print("✅ ALL ATTACK TYPES DEMONSTRATED!")
        print("="*70)
        print(f"\n📊 Summary:")
        print(f"   Attack Types Shown: {len(ATTACK_PATTERNS)}")
        print(f"   Normal Types Shown: {len(NORMAL_PATTERNS)}")
        print(f"   Total Predictions: {self.total_count}")
        print(f"\n👀 Check your dashboard to see all the detections!")
        print(f"   {DASHBOARD_URL}")
        print("="*70)


def main():
    """Main menu"""

    print("\n" + "="*70)
    print("🛡️  IDS-ML DASHBOARD ATTACK SIMULATOR")
    print("="*70)
    print("\nThis simulator sends attacks directly to your dashboard.")
    print("You'll see results update in real-time in your browser!")
    print("\nChoose a simulation mode:")
    print("\n1. Quick Demo (20 packets, 40% attacks) - RECOMMENDED")
    print("2. Balanced Test (30 packets, 50% attacks)")
    print("3. Heavy Attack Scenario (25 packets, 70% attacks)")
    print("4. Demonstrate All Attack Types - BEST FOR PRESENTATION")
    print("5. Custom Configuration")
    print("\n0. Exit")
    print("="*70)

    simulator = DashboardSimulator()

    try:
        choice = input("\nEnter your choice (1-5): ").strip()

        if choice == '1':
            print("\n🎯 Starting Quick Demo...")
            simulator.run_demo(num_packets=20, attack_probability=0.4, delay=2.0)

        elif choice == '2':
            print("\n🎯 Starting Balanced Test...")
            simulator.run_demo(num_packets=30, attack_probability=0.5, delay=1.5)

        elif choice == '3':
            print("\n🎯 Starting Heavy Attack Scenario...")
            simulator.run_demo(num_packets=25, attack_probability=0.7, delay=2.0)

        elif choice == '4':
            print("\n🎯 Demonstrating All Attack Types...")
            simulator.demonstrate_all_attacks()

        elif choice == '5':
            print("\n🎯 Custom Configuration:")
            num = int(input("   Number of packets (10-50): "))
            prob = float(input("   Attack probability (0.0-1.0): "))
            delay = float(input("   Delay between packets (1-5 seconds): "))
            simulator.run_demo(num_packets=num, attack_probability=prob, delay=delay)

        elif choice == '0':
            print("\nExiting... Goodbye!")
            return

        else:
            print("\n❌ Invalid choice!")

        print("\n✨ Simulation complete! Check your dashboard for results.\n")

    except KeyboardInterrupt:
        print("\n\n⚠️  Interrupted by user")
    except ValueError:
        print("\n❌ Invalid input! Please enter valid numbers.")
    except Exception as e:
        print(f"\n❌ Error: {e}")


if __name__ == "__main__":
    main()
