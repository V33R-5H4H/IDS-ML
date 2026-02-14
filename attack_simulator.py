"""
Attack Simulator for IDS-ML System
Automatically generates and sends random attack and normal traffic patterns
"""

import requests
import time
import random
from datetime import datetime
import json

# API Configuration
API_URL = 'http://localhost:8000'

# Attack patterns based on NSL-KDD dataset characteristics
ATTACK_PATTERNS = {
    'neptune': {
        'name': 'Neptune DoS Attack',
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
            'serror_rate': lambda: round(random.uniform(0.8, 1.0), 2),
            'srv_serror_rate': lambda: round(random.uniform(0.8, 1.0), 2),
            'dst_host_srv_count': lambda: random.randint(200, 255)
        }
    },

    'smurf': {
        'name': 'Smurf DoS Attack',
        'features': {
            'protocol_type': 'icmp',
            'service': 'ecr_i',
            'flag': 'SF',
            'src_bytes': lambda: random.randint(1000, 1500),
            'dst_bytes': lambda: 0,
            'duration': lambda: 0,
            'logged_in': lambda: 0,
            'count': lambda: random.randint(400, 511),
            'srv_count': lambda: random.randint(400, 511),
            'serror_rate': lambda: 0.0,
            'srv_serror_rate': lambda: 0.0,
            'dst_host_srv_count': lambda: random.randint(200, 255)
        }
    },

    'portsweep': {
        'name': 'Port Sweep Attack',
        'features': {
            'protocol_type': 'tcp',
            'service': random.choice(['private', 'http', 'ftp', 'telnet']),
            'flag': 'REJ',
            'src_bytes': lambda: random.randint(0, 100),
            'dst_bytes': lambda: random.randint(0, 100),
            'duration': lambda: random.randint(0, 5),
            'logged_in': lambda: 0,
            'count': lambda: random.randint(200, 400),
            'srv_count': lambda: random.randint(20, 50),
            'serror_rate': lambda: round(random.uniform(0.5, 1.0), 2),
            'srv_serror_rate': lambda: round(random.uniform(0.5, 1.0), 2),
            'dst_host_srv_count': lambda: random.randint(50, 150)
        }
    },

    'satan': {
        'name': 'Satan Probe Attack',
        'features': {
            'protocol_type': 'tcp',
            'service': random.choice(['http', 'ftp', 'telnet']),
            'flag': 'SF',
            'src_bytes': lambda: random.randint(100, 500),
            'dst_bytes': lambda: random.randint(5000, 10000),
            'duration': lambda: random.randint(0, 10),
            'logged_in': lambda: 0,
            'count': lambda: random.randint(1, 5),
            'srv_count': lambda: random.randint(1, 5),
            'serror_rate': lambda: 0.0,
            'srv_serror_rate': lambda: 0.0,
            'dst_host_srv_count': lambda: random.randint(20, 50)
        }
    },

    'ipsweep': {
        'name': 'IP Sweep Attack',
        'features': {
            'protocol_type': 'icmp',
            'service': 'eco_i',
            'flag': 'SF',
            'src_bytes': lambda: 8,
            'dst_bytes': lambda: 0,
            'duration': lambda: 0,
            'logged_in': lambda: 0,
            'count': lambda: random.randint(1, 10),
            'srv_count': lambda: random.randint(1, 10),
            'serror_rate': lambda: 0.0,
            'srv_serror_rate': lambda: 0.0,
            'dst_host_srv_count': lambda: random.randint(100, 255)
        }
    },

    'back': {
        'name': 'Back DoS Attack',
        'features': {
            'protocol_type': 'tcp',
            'service': 'http',
            'flag': 'SF',
            'src_bytes': lambda: random.randint(300, 600),
            'dst_bytes': lambda: random.randint(10000, 20000),
            'duration': lambda: random.randint(5, 30),
            'logged_in': lambda: 1,
            'count': lambda: random.randint(50, 150),
            'srv_count': lambda: random.randint(50, 150),
            'serror_rate': lambda: 0.0,
            'srv_serror_rate': lambda: 0.0,
            'dst_host_srv_count': lambda: random.randint(10, 50)
        }
    },

    'teardrop': {
        'name': 'Teardrop DoS Attack',
        'features': {
            'protocol_type': 'udp',
            'service': 'private',
            'flag': 'SF',
            'src_bytes': lambda: random.randint(0, 50),
            'dst_bytes': lambda: random.randint(0, 50),
            'duration': lambda: 0,
            'logged_in': lambda: 0,
            'count': lambda: random.randint(1, 10),
            'srv_count': lambda: random.randint(1, 10),
            'serror_rate': lambda: 0.0,
            'srv_serror_rate': lambda: 0.0,
            'dst_host_srv_count': lambda: random.randint(1, 10)
        }
    },

    'pod': {
        'name': 'Ping of Death Attack',
        'features': {
            'protocol_type': 'icmp',
            'service': 'eco_i',
            'flag': 'SF',
            'src_bytes': lambda: random.randint(65000, 70000),
            'dst_bytes': lambda: 0,
            'duration': lambda: 0,
            'logged_in': lambda: 0,
            'count': lambda: random.randint(1, 5),
            'srv_count': lambda: random.randint(1, 5),
            'serror_rate': lambda: 0.0,
            'srv_serror_rate': lambda: 0.0,
            'dst_host_srv_count': lambda: random.randint(1, 10)
        }
    }
}

# Normal traffic patterns
NORMAL_PATTERNS = {
    'http_normal': {
        'name': 'Normal HTTP Traffic',
        'features': {
            'protocol_type': 'tcp',
            'service': 'http',
            'flag': 'SF',
            'src_bytes': lambda: random.randint(100, 500),
            'dst_bytes': lambda: random.randint(1000, 10000),
            'duration': lambda: random.randint(0, 60),
            'logged_in': lambda: random.choice([0, 1]),
            'count': lambda: random.randint(1, 20),
            'srv_count': lambda: random.randint(1, 20),
            'serror_rate': lambda: 0.0,
            'srv_serror_rate': lambda: 0.0,
            'dst_host_srv_count': lambda: random.randint(1, 30)
        }
    },

    'ftp_normal': {
        'name': 'Normal FTP Traffic',
        'features': {
            'protocol_type': 'tcp',
            'service': 'ftp',
            'flag': 'SF',
            'src_bytes': lambda: random.randint(50, 200),
            'dst_bytes': lambda: random.randint(500, 5000),
            'duration': lambda: random.randint(0, 300),
            'logged_in': lambda: 1,
            'count': lambda: random.randint(1, 10),
            'srv_count': lambda: random.randint(1, 10),
            'serror_rate': lambda: 0.0,
            'srv_serror_rate': lambda: 0.0,
            'dst_host_srv_count': lambda: random.randint(1, 15)
        }
    },

    'smtp_normal': {
        'name': 'Normal SMTP Traffic',
        'features': {
            'protocol_type': 'tcp',
            'service': 'smtp',
            'flag': 'SF',
            'src_bytes': lambda: random.randint(200, 1000),
            'dst_bytes': lambda: random.randint(200, 1000),
            'duration': lambda: random.randint(0, 120),
            'logged_in': lambda: 1,
            'count': lambda: random.randint(1, 5),
            'srv_count': lambda: random.randint(1, 5),
            'serror_rate': lambda: 0.0,
            'srv_serror_rate': lambda: 0.0,
            'dst_host_srv_count': lambda: random.randint(1, 10)
        }
    },

    'ssh_normal': {
        'name': 'Normal SSH Traffic',
        'features': {
            'protocol_type': 'tcp',
            'service': 'ssh',
            'flag': 'SF',
            'src_bytes': lambda: random.randint(1000, 5000),
            'dst_bytes': lambda: random.randint(1000, 5000),
            'duration': lambda: random.randint(60, 600),
            'logged_in': lambda: 1,
            'count': lambda: random.randint(1, 3),
            'srv_count': lambda: random.randint(1, 3),
            'serror_rate': lambda: 0.0,
            'srv_serror_rate': lambda: 0.0,
            'dst_host_srv_count': lambda: random.randint(1, 5)
        }
    }
}


class TrafficSimulator:
    """Simulates network traffic for IDS testing"""

    def __init__(self, api_url=API_URL):
        self.api_url = api_url
        self.stats = {
            'total_sent': 0,
            'attacks_sent': 0,
            'normal_sent': 0,
            'successful': 0,
            'failed': 0,
            'attack_types': {}
        }

    def generate_features(self, pattern):
        """Generate features from pattern"""
        features = {}
        for key, value in pattern['features'].items():
            if callable(value):
                features[key] = value()
            else:
                features[key] = value
        return features

    def send_traffic(self, features, traffic_type, pattern_name):
        """Send traffic to API"""
        try:
            response = requests.post(
                f'{self.api_url}/predict',
                json=features,
                timeout=5
            )

            if response.status_code == 200:
                result = response.json()
                self.stats['successful'] += 1

                # Log result
                timestamp = datetime.now().strftime('%H:%M:%S')
                print(f"[{timestamp}] {traffic_type:6s} | {pattern_name:20s} → "
                      f"{result['prediction']:15s} | "
                      f"Conf: {result['confidence']*100:5.1f}% | "
                      f"Severity: {result['severity']:6s}")

                return result
            else:
                self.stats['failed'] += 1
                print(f"❌ Request failed: {response.status_code}")
                return None

        except Exception as e:
            self.stats['failed'] += 1
            print(f"❌ Error: {e}")
            return None

    def simulate_attack(self, attack_type=None):
        """Simulate a random or specific attack"""
        if attack_type is None:
            attack_type = random.choice(list(ATTACK_PATTERNS.keys()))

        pattern = ATTACK_PATTERNS[attack_type]
        features = self.generate_features(pattern)

        self.stats['total_sent'] += 1
        self.stats['attacks_sent'] += 1
        self.stats['attack_types'][attack_type] =             self.stats['attack_types'].get(attack_type, 0) + 1

        return self.send_traffic(features, '🔴 ATTACK', pattern['name'])

    def simulate_normal(self, traffic_type=None):
        """Simulate normal traffic"""
        if traffic_type is None:
            traffic_type = random.choice(list(NORMAL_PATTERNS.keys()))

        pattern = NORMAL_PATTERNS[traffic_type]
        features = self.generate_features(pattern)

        self.stats['total_sent'] += 1
        self.stats['normal_sent'] += 1

        return self.send_traffic(features, '🟢 NORMAL', pattern['name'])

    def run_simulation(self, duration=60, attack_probability=0.3, delay=1.0):
        """Run continuous simulation"""
        print("=" * 90)
        print("IDS-ML TRAFFIC SIMULATOR")
        print("=" * 90)
        print(f"Duration: {duration} seconds")
        print(f"Attack Probability: {attack_probability * 100:.0f}%")
        print(f"Delay between packets: {delay} seconds")
        print("=" * 90)
        print()

        start_time = time.time()

        try:
            while time.time() - start_time < duration:
                # Randomly decide if this is an attack or normal traffic
                if random.random() < attack_probability:
                    self.simulate_attack()
                else:
                    self.simulate_normal()

                time.sleep(delay)

        except KeyboardInterrupt:
            print("\n\n⚠️  Simulation interrupted by user")

        self.print_summary()

    def run_batch(self, num_packets=20, attack_probability=0.3, delay=0.5):
        """Run a batch of simulations"""
        print("=" * 90)
        print("IDS-ML BATCH TRAFFIC SIMULATOR")
        print("=" * 90)
        print(f"Total packets: {num_packets}")
        print(f"Attack Probability: {attack_probability * 100:.0f}%")
        print("=" * 90)
        print()

        for i in range(num_packets):
            print(f"\n[Packet {i+1}/{num_packets}]")

            if random.random() < attack_probability:
                self.simulate_attack()
            else:
                self.simulate_normal()

            if i < num_packets - 1:
                time.sleep(delay)

        self.print_summary()

    def demonstrate_all_attacks(self):
        """Demonstrate one of each attack type"""
        print("=" * 90)
        print("DEMONSTRATING ALL ATTACK TYPES")
        print("=" * 90)
        print()

        for attack_type in ATTACK_PATTERNS.keys():
            print(f"\n--- Testing: {ATTACK_PATTERNS[attack_type]['name']} ---")
            self.simulate_attack(attack_type)
            time.sleep(1)

        print("\n--- Testing Normal Traffic ---")
        for normal_type in NORMAL_PATTERNS.keys():
            self.simulate_normal(normal_type)
            time.sleep(1)

        self.print_summary()

    def print_summary(self):
        """Print simulation statistics"""
        print("\n")
        print("=" * 90)
        print("SIMULATION SUMMARY")
        print("=" * 90)
        print(f"Total Packets Sent:     {self.stats['total_sent']}")
        print(f"  ├─ Normal Traffic:    {self.stats['normal_sent']}")
        print(f"  └─ Attack Traffic:    {self.stats['attacks_sent']}")
        print(f"\nSuccessful Requests:    {self.stats['successful']}")
        print(f"Failed Requests:        {self.stats['failed']}")

        if self.stats['attack_types']:
            print(f"\nAttack Types Distribution:")
            for attack, count in sorted(self.stats['attack_types'].items()):
                print(f"  ├─ {attack:15s}: {count}")

        print("=" * 90)


def main():
    """Main simulation menu"""
    simulator = TrafficSimulator()

    print("\n" + "=" * 90)
    print("IDS-ML TRAFFIC SIMULATOR")
    print("=" * 90)
    print("\nChoose simulation mode:")
    print("\n1. Quick Demo (20 packets, 30% attacks)")
    print("2. Continuous Simulation (60 seconds)")
    print("3. Heavy Attack Simulation (70% attacks)")
    print("4. Demonstrate All Attack Types")
    print("5. Custom Simulation")
    print("\n0. Exit")
    print("=" * 90)

    try:
        choice = input("\nEnter choice (1-5): ").strip()

        if choice == '1':
            print("\n🚀 Starting Quick Demo...")
            simulator.run_batch(num_packets=20, attack_probability=0.3, delay=0.5)

        elif choice == '2':
            print("\n🚀 Starting Continuous Simulation...")
            simulator.run_simulation(duration=60, attack_probability=0.3, delay=1.0)

        elif choice == '3':
            print("\n🚀 Starting Heavy Attack Simulation...")
            simulator.run_batch(num_packets=30, attack_probability=0.7, delay=0.5)

        elif choice == '4':
            print("\n🚀 Demonstrating All Attack Types...")
            simulator.demonstrate_all_attacks()

        elif choice == '5':
            num = int(input("Number of packets: "))
            prob = float(input("Attack probability (0.0-1.0): "))
            delay = float(input("Delay between packets (seconds): "))
            simulator.run_batch(num_packets=num, attack_probability=prob, delay=delay)

        elif choice == '0':
            print("\nExiting...")
            return

        else:
            print("\n❌ Invalid choice!")

    except KeyboardInterrupt:
        print("\n\n⚠️  Interrupted by user")
    except Exception as e:
        print(f"\n❌ Error: {e}")


if __name__ == "__main__":
    main()
