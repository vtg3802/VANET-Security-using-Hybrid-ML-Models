import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import random

class VANETDatasetGenerator:
    def __init__(self, seed=42):
        np.random.seed(seed)
        random.seed(seed)
        
        # Vehicle pool
        self.vehicle_ids = [1000 + i for i in range(100)]
        
        # Track vehicle states for consistency
        self.vehicle_states = {}
        
        # Define realistic ranges
        self.config = {
            'lat_range': (35.0, 35.5),
            'lon_range': (-119.5, -120.0),
            'speed_range': (30, 85),
            'signal_range': (-95, -45),
            'rsu_distance_range': (50, 500),
            'packet_loss_normal': (0.0, 0.3),
            'packet_loss_dos': (0.3, 0.95),
            'latency_normal': (15, 80),
            'latency_dos': (80, 250),
        }
        
        # Attack type mapping: Normal=0, DOS=1, Spoofed=2, Sybil=3
        self.attack_types = {
            'normal': 0,
            'dos': 1,
            'spoofed': 2,
            'sybil': 3
        }
        
    def get_vehicle_state(self, vehicle_id, timestamp):
        """Get or initialize vehicle state for consistency"""
        if vehicle_id not in self.vehicle_states:
            self.vehicle_states[vehicle_id] = {
                'lat': np.random.uniform(*self.config['lat_range']),
                'lon': np.random.uniform(*self.config['lon_range']),
                'speed': np.random.uniform(30, 85),
                'direction': np.random.uniform(0, 360),
                'lane_id': np.random.choice([1, 2, 3, 4]),
                'last_update': timestamp
            }
        return self.vehicle_states[vehicle_id]
    
    def update_vehicle_state(self, vehicle_id, state_update):
        """Update vehicle state for temporal consistency"""
        if vehicle_id in self.vehicle_states:
            self.vehicle_states[vehicle_id].update(state_update)
    
    def generate_normal_traffic(self, timestamp, vehicle_id):
        """Generate normal traffic patterns with consistent vehicle movement"""
        state = self.get_vehicle_state(vehicle_id, timestamp)
        
        # Calculate time delta for consistent movement
        time_delta = 0.001  # 1ms in seconds
        
        # Update position based on speed and direction
        speed_ms = state['speed'] / 3.6  # Convert km/h to m/s
        lat_change = (speed_ms * time_delta * np.cos(np.radians(state['direction']))) / 111320
        lon_change = (speed_ms * time_delta * np.sin(np.radians(state['direction']))) / (111320 * np.cos(np.radians(state['lat'])))
        
        new_lat = state['lat'] + lat_change + np.random.normal(0, 0.00001)
        new_lon = state['lon'] + lon_change + np.random.normal(0, 0.00001)
        
        # Realistic speed changes
        new_speed = state['speed'] + np.random.normal(0, 2)
        new_speed = np.clip(new_speed, 30, 85)
        
        # Small direction changes
        new_direction = (state['direction'] + np.random.normal(0, 5)) % 360
        
        # Update state
        self.update_vehicle_state(vehicle_id, {
            'lat': new_lat,
            'lon': new_lon,
            'speed': new_speed,
            'direction': new_direction,
            'last_update': timestamp
        })
        
        return {
            'vehicle_id': vehicle_id,
            'timestamp': timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'latitude': new_lat,
            'longitude': new_lon,
            'speed': new_speed,
            'acceleration': np.random.uniform(-2, 2),
            'direction': new_direction,
            'lane_id': state['lane_id'],
            'packet_loss_rate': np.random.uniform(0, 0.2),
            'signal_strength': np.random.uniform(-95, -50),
            'message_frequency': np.random.choice([5, 10]),
            'data_volume': np.random.uniform(80, 125),
            'latency': np.random.uniform(15, 80),
            'weather_condition': np.random.choice(['sunny', 'rainy', 'foggy']),
            'traffic_density': np.random.randint(10, 100),
            'road_type': np.random.choice(['highway', 'urban']),
            'RSU_distance': np.random.uniform(50, 500),
            'threat_type': self.attack_types['normal']
        }
    
    def generate_dos_attack(self, timestamp, vehicle_id):
        """
        DOS Attack (threat_type=1)
        - Floods network with high message frequency
        - Large data volumes
        - Causes high packet loss and latency for all
        """
        data = self.generate_normal_traffic(timestamp, vehicle_id)
        
        # DOS characteristics - matching your sample data patterns
        data['message_frequency'] = np.random.choice([40, 45, 50])
        data['data_volume'] = np.random.uniform(90, 140)
        data['packet_loss_rate'] = np.random.uniform(0.8, 0.95)
        data['latency'] = np.random.uniform(150, 250)
        data['signal_strength'] = np.random.uniform(-70, -60)
        data['threat_type'] = self.attack_types['dos']
        
        return data
    
    def generate_spoofing_attack(self, timestamp, vehicle_id):
        """
        Spoofing Attack (threat_type=2)
        - False position/speed/acceleration data
        - Inconsistent trajectories (teleportation)
        - Impossible physical movements
        """
        data = self.generate_normal_traffic(timestamp, vehicle_id)
        
        spoof_type = np.random.choice(['position', 'speed', 'trajectory'])
        
        if spoof_type == 'position':
            # Teleportation - impossible position jump
            data['latitude'] = np.random.uniform(34.5, 36.0)
            data['longitude'] = np.random.uniform(-118.5, -121.0)
            data['signal_strength'] = np.random.uniform(-65, -50)
            data['RSU_distance'] = np.random.uniform(300, 500)
            
        elif spoof_type == 'speed':
            # Impossible speed values
            data['speed'] = np.random.uniform(150, 300)
            data['acceleration'] = np.random.uniform(-10, 10)
            
        elif spoof_type == 'trajectory':
            # Inconsistent movement
            data['direction'] = np.random.uniform(0, 360)
            data['acceleration'] = np.random.uniform(-8, 8)
        
        data['packet_loss_rate'] = np.random.uniform(0.1, 0.3)
        data['latency'] = np.random.uniform(20, 90)
        data['message_frequency'] = 10
        data['threat_type'] = self.attack_types['spoofed']
        
        return data
    
    def generate_sybil_attack(self, timestamp, base_vehicle_id, sybil_cluster):
        """
        Sybil Attack (threat_type=3)
        - Multiple fake IDs from same physical location
        - Similar signal characteristics across fake IDs
        - Clustered in space and time
        """
        # Generate fake vehicle ID in a different range
        fake_vehicle_id = np.random.randint(5000, 6000)
        
        # All Sybil nodes share similar characteristics
        shared_lat = sybil_cluster['lat'] + np.random.uniform(-0.001, 0.001)
        shared_lon = sybil_cluster['lon'] + np.random.uniform(-0.001, 0.001)
        shared_signal = sybil_cluster['signal'] + np.random.uniform(-3, 3)
        shared_rsu_distance = sybil_cluster['rsu_distance'] + np.random.uniform(-20, 20)
        
        return {
            'vehicle_id': fake_vehicle_id,
            'timestamp': timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'latitude': shared_lat,
            'longitude': shared_lon,
            'speed': np.random.uniform(30, 85),
            'acceleration': np.random.uniform(-2, 2),
            'direction': np.random.uniform(0, 360),
            'lane_id': sybil_cluster['lane_id'],
            'packet_loss_rate': np.random.uniform(0.1, 0.3),
            'signal_strength': shared_signal,
            'message_frequency': 10,
            'data_volume': np.random.uniform(80, 120),
            'latency': np.random.uniform(30, 60),
            'weather_condition': np.random.choice(['sunny', 'rainy', 'foggy']),
            'traffic_density': np.random.randint(80, 150),
            'road_type': sybil_cluster['road_type'],
            'RSU_distance': shared_rsu_distance,
            'threat_type': self.attack_types['sybil']
        }
    
    def generate_dataset(self, n_samples=10000, attack_distribution=None):
        """
        Generate complete dataset with specified attack distribution
        """
        if attack_distribution is None:
            attack_distribution = {
                'normal': 0.70,
                'dos': 0.10,
                'spoofed': 0.10,
                'sybil': 0.10
            }
        
        data = []
        start_time = datetime(2025, 1, 1, 0, 0, 0)
        
        # Calculate samples per type
        samples_per_type = {
            k: int(n_samples * v) for k, v in attack_distribution.items()
        }
        
        # Adjust to reach exactly n_samples
        diff = n_samples - sum(samples_per_type.values())
        samples_per_type['normal'] += diff
        
        # Generate all samples with proper time increments
        sample_count = 0
        
        # Generate normal traffic
        for i in range(samples_per_type['normal']):
            vehicle_id = np.random.choice(self.vehicle_ids)
            data.append(self.generate_normal_traffic(start_time, vehicle_id))
            start_time += timedelta(milliseconds=1)
            sample_count += 1
        
        # Generate DOS attacks
        for i in range(samples_per_type['dos']):
            vehicle_id = np.random.choice(self.vehicle_ids)
            data.append(self.generate_dos_attack(start_time, vehicle_id))
            start_time += timedelta(milliseconds=1)
            sample_count += 1
        
        # Generate Spoofing attacks
        for i in range(samples_per_type['spoofed']):
            vehicle_id = np.random.choice(self.vehicle_ids)
            data.append(self.generate_spoofing_attack(start_time, vehicle_id))
            start_time += timedelta(milliseconds=1)
            sample_count += 1
        
        # Generate Sybil attacks
        sybil_cluster = {
            'lat': np.random.uniform(*self.config['lat_range']),
            'lon': np.random.uniform(*self.config['lon_range']),
            'signal': np.random.uniform(-65, -55),
            'rsu_distance': np.random.uniform(100, 300),
            'lane_id': np.random.choice([1, 2, 3, 4]),
            'road_type': np.random.choice(['highway', 'urban'])
        }
        
        for i in range(samples_per_type['sybil']):
            base_vehicle = np.random.choice(self.vehicle_ids)
            # Create new cluster occasionally
            if i % 50 == 0:
                sybil_cluster = {
                    'lat': np.random.uniform(*self.config['lat_range']),
                    'lon': np.random.uniform(*self.config['lon_range']),
                    'signal': np.random.uniform(-65, -55),
                    'rsu_distance': np.random.uniform(100, 300),
                    'lane_id': np.random.choice([1, 2, 3, 4]),
                    'road_type': np.random.choice(['highway', 'urban'])
                }
            data.append(self.generate_sybil_attack(start_time, base_vehicle, sybil_cluster))
            start_time += timedelta(milliseconds=1)
            sample_count += 1
        
        # Shuffle to mix attack types
        random.shuffle(data)
        
        # Re-assign timestamps in order
        current_time = datetime(2025, 1, 1, 0, 0, 0)
        for record in data:
            record['timestamp'] = current_time.strftime('%Y-%m-%d %H:%M:%S')
            current_time += timedelta(milliseconds=1)
        
        return pd.DataFrame(data)

def main():
    # Initialize generator
    generator = VANETDatasetGenerator(seed=42)
    
    # Define attack distribution
    attack_distribution = {
        'normal': 0.70,    # 70% normal traffic
        'dos': 0.10,       # 10% DOS attacks
        'spoofed': 0.10,   # 10% Spoofing attacks
        'sybil': 0.10      # 10% Sybil attacks
    }
    
    # Generate dataset
    print("Generating VANET dataset...")
    df = generator.generate_dataset(n_samples=10000, attack_distribution=attack_distribution)
    
    # Format the output to match your desired format
    # Remove spaces from column names
    df.columns = df.columns.str.replace(' ', '')
    
    # Reorder columns to match your sample
    column_order = [
        'vehicle_id', 'timestamp', 'latitude', 'longitude', 'speed', 
        'acceleration', 'direction', 'lane_id', 'packet_loss_rate', 
        'signal_strength', 'message_frequency', 'data_volume', 'latency',
        'weather_condition', 'traffic_density', 'road_type', 'RSU_distance', 
        'threat_type'
    ]
    df = df[column_order]
    
    # Save to CSV with no spaces
    output_file = 'enhanced_vanet_dataset.csv'
    df.to_csv(output_file, index=False)
    
    print(f"Dataset saved to '{output_file}'")
    print(f"Total samples: {len(df)}")
    
    # Print threat distribution
    print("\nThreat Type Distribution:")
    threat_counts = df['threat_type'].value_counts().sort_index()
    threat_names = {0: 'Normal', 1: 'DOS', 2: 'Spoofed', 3: 'Sybil'}
    for threat_type, count in threat_counts.items():
        percentage = (count / len(df)) * 100
        print(f"  {threat_type} ({threat_names[threat_type]}): {count} samples ({percentage:.1f}%)")
    
    # Show sample of data in the format you want
    print("\nSample of generated data:")
    print(df.head(25).to_string(index=False))
    
    return df

if __name__ == "__main__":
    df = main()