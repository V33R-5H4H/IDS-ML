"""
Enhanced Dashboard Attack Simulator for IDS-ML System
Shows detailed attack data being sent for better understanding
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

# Attack patterns with detailed explanations
ATTACK_PATTERNS = {
    'neptune': {
        'name': 'Neptune DoS Attack',
        'description': 'SYN flood attack overwhelming the server',
        'why_detected': 'High connection count + SYN errors + No data transfer',
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
        'why_detected': 'ICMP protocol + Large source bytes + Many connections',
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
        'why_detected': 'REJ flag + High error rate + Many different connections',
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
        'why_detected': 'Multiple service connections + Scanning pattern',
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
        'why_detected': 'ICMP pings to many different hosts',
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
        'why_detected': 'HTTP service + Unusual data pattern + Many connections',
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
        'why_detected': 'UDP + Fragmented packets + Low byte count',
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
        'why_detected': 'ICMP + Abnormally large packet size (>65KB)',
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
        'why_normal': 'Normal byte counts + Low connection count + No errors',
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
        'why_normal': 'Logged in + FTP service + Normal data transfer',
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
        'why_normal': 'SMTP service + Balanced bytes + Logged in',
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
        'why_normal': 'SSH service + Encrypted data + Authenticated',
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


class EnhancedSimulator:
    """Enhanced simulator with detailed output"""

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

    def print_feature_table(self, features, pattern_name, is_attack):
        """Print features in a nice table format"""

        icon = "🔴" if is_attack else "🟢"
        print(f"\n{icon} {'='*68}")
        print(f"   {pattern_name.upper()}")
        print(f"{'='*70}")

        # Print key indicators
        print(f"\n📊 Network Features Being Sent:")
        print(f"   ├─ Protocol: {features['protocol_type'].upper()}")
        print(f"   ├─ Service: {features['service']}")
        print(f"   ├─ Flag: {features['flag']}")
        print(f"   ├─ Source Bytes: {features['src_bytes']:,}")
        print(f"   ├─ Dest Bytes: {features['dst_bytes']:,}")
        print(f"   ├─ Duration: {features['duration']}s")
        print(f"   ├─ Logged In: {'Yes' if features['logged_in'] else 'No'}")
        print(f"   ├─ Connection Count: {features['count']}")
        print(f"   ├─ Service Count: {features['srv_count']}")
        print(f"   ├─ SYN Error Rate: {features['serror_rate']*100:.0f}%")
        print(f"   ├─ Srv Error Rate: {features['srv_serror_rate']*100:.0f}%")
        print(f"   └─ Dst Host Count: {features['dst_host_srv_count']}")

    def send_to_api(self, features, traffic_type, pattern_name, pattern):
        """Send traffic to API with detailed output"""

        is_attack = traffic_type == 'ATTACK'

        # Print feature details
        self.print_feature_table(features, pattern_name, is_attack)

        # Print why it's detected as attack/normal
        if is_attack:
            print(f"\n🔍 Why This is Detected as Attack:")
            print(f"   {pattern['why_detected']}")
        else:
            print(f"\n✅ Why This is Normal Traffic:")
            print(f"   {pattern['why_normal']}")

        print(f"\n⏳ Sending to API...")

        try:
            response = requests.post(
                f'{API_URL}/predict',
                json=features,
                timeout=5
            )

            if response.status_code == 200:
                result = response.json()
                self.total_count += 1

                # Print API response
                print(f"\n✅ API Response:")
                print(f"   ├─ Prediction: {result['prediction']}")
                print(f"   ├─ Confidence: {result['confidence']*100:.1f}%")
                print(f"   ├─ Is Attack: {'Yes' if result['is_attack'] else 'No'}")
                print(f"   └─ Severity: {result['severity']}")

                # Verify if prediction matches expectation
                if is_attack and result['is_attack']:
                    print(f"\n   ✅ Correctly detected as ATTACK!")
                elif not is_attack and not result['is_attack']:
                    print(f"\n   ✅ Correctly detected as NORMAL!")
                else:
                    print(f"\n   ⚠️  Unexpected result!")

                print(f"\n👁️  Check dashboard for live update!")

                return result
            else:
                print(f"\n❌ API Error: {response.status_code}")
                return None

        except Exception as e:
            print(f"\n❌ Connection Error: {e}")
            print("   Make sure backend is running on http://localhost:8000")
            return None

    def simulate_attack(self, attack_type=None):
        """Send an attack with details"""
        if attack_type is None:
            attack_type = random.choice(list(ATTACK_PATTERNS.keys()))

        pattern = ATTACK_PATTERNS[attack_type]
        features = self.generate_features(pattern)

        self.attack_count += 1
        return self.send_to_api(features, 'ATTACK', pattern['name'], pattern)

    def simulate_normal(self, traffic_type=None):
        """Send normal traffic with details"""
        if traffic_type is None:
            traffic_type = random.choice(list(NORMAL_PATTERNS.keys()))

        pattern = NORMAL_PATTERNS[traffic_type]
        features = self.generate_features(pattern)

        self.normal_count += 1
        return self.send_to_api(features, 'NORMAL', pattern['name'], pattern)

    def run_demo(self, num_packets=20, attack_probability=0.4, delay=3.0):
        """Run simulation with detailed output"""

        print("\n" + "="*70)
        print("🚀 IDS-ML ENHANCED ATTACK SIMULATOR")
        print("="*70)
        print(f"\n📊 Configuration:")
        print(f"   Total Packets: {num_packets}")
        print(f"   Attack Rate: {attack_probability*100:.0f}%")
        print(f"   Delay: {delay} seconds between packets")
        print(f"\n🌐 Dashboard: {DASHBOARD_URL}")
        print(f"\n⏳ Starting in 3 seconds...")
        print("   Watch your browser dashboard AND terminal for details!")
        print("="*70)

        time.sleep(1)
        try:
            webbrowser.open(DASHBOARD_URL)
        except:
            pass

        time.sleep(2)

        for i in range(num_packets):
            print(f"\n\n{'█'*70}")
            print(f"PACKET {i+1}/{num_packets}")
            print(f"{'█'*70}")

            if random.random() < attack_probability:
                self.simulate_attack()
            else:
                self.simulate_normal()

            if i < num_packets - 1:
                print(f"\n⏱️  Waiting {delay} seconds before next packet...")
                time.sleep(delay)

        self.print_summary()

    def demonstrate_all_attacks(self):
        """Show one of each attack type with details"""

        print("\n" + "="*70)
        print("🎯 DEMONSTRATING ALL ATTACK TYPES (WITH DETAILS)")
        print("="*70)
        print(f"\n🌐 Dashboard: {DASHBOARD_URL}")
        print("\n⏳ Starting in 3 seconds...")
        print("   Watch both terminal and dashboard!")
        print("="*70)

        time.sleep(1)
        try:
            webbrowser.open(DASHBOARD_URL)
        except:
            pass

        time.sleep(2)

        packet_num = 1

        # Show all attacks
        print(f"\n\n{'█'*70}")
        print("DEMONSTRATING ATTACK PATTERNS")
        print(f"{'█'*70}")

        for attack_type, pattern in ATTACK_PATTERNS.items():
            print(f"\n\n{'█'*70}")
            print(f"PACKET {packet_num}/{len(ATTACK_PATTERNS)+len(NORMAL_PATTERNS)}")
            print(f"{'█'*70}")

            print(f"\n📝 Description: {pattern['description']}")
            self.simulate_attack(attack_type)

            packet_num += 1
            print(f"\n⏱️  Waiting 3 seconds...")
            time.sleep(3)

        # Show normal traffic examples
        print(f"\n\n{'█'*70}")
        print("DEMONSTRATING NORMAL TRAFFIC PATTERNS")
        print(f"{'█'*70}")

        for normal_type, pattern in NORMAL_PATTERNS.items():
            print(f"\n\n{'█'*70}")
            print(f"PACKET {packet_num}/{len(ATTACK_PATTERNS)+len(NORMAL_PATTERNS)}")
            print(f"{'█'*70}")

            print(f"\n📝 Description: {pattern['description']}")
            self.simulate_normal(normal_type)

            packet_num += 1
            print(f"\n⏱️  Waiting 3 seconds...")
            time.sleep(3)

        self.print_summary()

    def print_summary(self):
        """Print detailed summary"""
        print(f"\n\n" + "="*70)
        print("✅ SIMULATION COMPLETE!")
        print("="*70)
        print(f"\n📊 Final Statistics:")
        print(f"   ├─ Total Packets Sent: {self.total_count}")
        print(f"   ├─ Attack Traffic: {self.attack_count} ({self.attack_count/max(self.total_count,1)*100:.0f}%)")
        print(f"   └─ Normal Traffic: {self.normal_count} ({self.normal_count/max(self.total_count,1)*100:.0f}%)")
        print(f"\n👀 View complete results on dashboard:")
        print(f"   {DASHBOARD_URL}")
        print(f"\n💡 Dashboard shows:")
        print(f"   • Total Predictions: {self.total_count}")
        print(f"   • Attacks Detected: (check dashboard)")
        print(f"   • Recent Predictions with confidence scores")
        print("="*70)


def main():
    """Main menu"""

    print("\n" + "="*70)
    print("🛡️  IDS-ML ENHANCED ATTACK SIMULATOR")
    print("="*70)
    print("\nThis simulator shows detailed attack data and why it's detected.")
    print("You'll see both terminal details AND dashboard updates!")
    print("\nChoose a simulation mode:")
    print("\n1. Quick Demo (10 packets, 50% attacks) - RECOMMENDED")
    print("2. Balanced Test (15 packets, 50% attacks)")
    print("3. Heavy Attack Scenario (12 packets, 75% attacks)")
    print("4. Demonstrate All Attack Types - BEST FOR PRESENTATION")
    print("5. Custom Configuration")
    print("\n0. Exit")
    print("="*70)

    simulator = EnhancedSimulator()

    try:
        choice = input("\nEnter your choice (1-5): ").strip()

        if choice == '1':
            print("\n🎯 Starting Quick Demo...")
            simulator.run_demo(num_packets=10, attack_probability=0.5, delay=3.0)

        elif choice == '2':
            print("\n🎯 Starting Balanced Test...")
            simulator.run_demo(num_packets=15, attack_probability=0.5, delay=3.0)

        elif choice == '3':
            print("\n🎯 Starting Heavy Attack Scenario...")
            simulator.run_demo(num_packets=12, attack_probability=0.75, delay=3.0)

        elif choice == '4':
            print("\n🎯 Demonstrating All Attack Types...")
            simulator.demonstrate_all_attacks()

        elif choice == '5':
            print("\n🎯 Custom Configuration:")
            num = int(input("   Number of packets (5-30): "))
            prob = float(input("   Attack probability (0.0-1.0): "))
            delay = float(input("   Delay between packets (2-5 seconds): "))
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
