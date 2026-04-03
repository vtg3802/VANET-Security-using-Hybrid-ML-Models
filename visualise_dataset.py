# analyze_attack_patterns_fixed.py
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from scipy import stats
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

class AttackPatternAnalyzer:
    def __init__(self, df):
        self.df = df
        self.attack_types = df['threat_type'].unique()
        
    def analyze_temporal_patterns(self):
        """Analyze temporal characteristics of different attacks"""
        print("="*60)
        print("TEMPORAL ATTACK PATTERN ANALYSIS")
        print("="*60)
        
        # Convert timestamp to datetime if string
        if self.df['timestamp'].dtype == 'object':
            self.df['timestamp'] = pd.to_datetime(self.df['timestamp'])
        
        # Group attacks by type and analyze temporal clustering
        for attack in self.attack_types:
            if attack == 0:  # Skip normal traffic
                continue
                
            attack_data = self.df[self.df['threat_type'] == attack]
            if len(attack_data) > 1:
                # Calculate inter-arrival times
                attack_data = attack_data.sort_values('timestamp')
                time_diffs = attack_data['timestamp'].diff().dt.total_seconds().dropna()
                
                print(f"\nAttack Type: {attack}")
                print(f"  Total instances: {len(attack_data)}")
                print(f"  Mean inter-arrival time: {time_diffs.mean():.3f} seconds")
                print(f"  Std dev: {time_diffs.std():.3f} seconds")
                print(f"  Burst detection (< 1 sec): {(time_diffs < 1).sum()} instances")
    
    def analyze_network_characteristics(self):
        """Analyze network-level characteristics for each attack type"""
        
        features = ['packet_loss_rate', 'latency', 'signal_strength', 
                   'message_frequency', 'data_volume', 'RSU_distance']
        
        results = {}
        
        for attack in self.attack_types:
            attack_data = self.df[self.df['threat_type'] == attack]
            results[attack] = {}
            
            for feature in features:
                if feature in attack_data.columns:
                    results[attack][feature] = {
                        'mean': attack_data[feature].mean(),
                        'std': attack_data[feature].std(),
                        'median': attack_data[feature].median()
                    }
        
        return results
    
    def detect_attack_signatures(self):
        """Identify unique signatures for each attack type"""
        
        signatures = {}
        
        # Normal baseline
        normal_data = self.df[self.df['threat_type'] == 0]
        
        for attack in self.attack_types:
            if attack == 0:
                continue
                
            attack_data = self.df[self.df['threat_type'] == attack]
            signature = {}
            
            # Compare distributions with normal traffic
            for col in ['packet_loss_rate', 'latency', 'speed', 'data_volume']:
                if col in self.df.columns:
                    # Perform statistical test
                    if len(attack_data) > 0 and len(normal_data) > 0:
                        statistic, pvalue = stats.ttest_ind(
                            attack_data[col].dropna(), 
                            normal_data[col].dropna()
                        )
                        
                        if pvalue < 0.001:  # Highly significant difference
                            signature[col] = {
                                'significant': True,
                                'attack_mean': attack_data[col].mean(),
                                'normal_mean': normal_data[col].mean(),
                                'ratio': attack_data[col].mean() / (normal_data[col].mean() + 0.001)
                            }
            
            signatures[attack] = signature
        
        return signatures
    
    def plot_attack_patterns(self):
        """Create comprehensive visualizations of attack patterns"""
        
        fig, axes = plt.subplots(3, 3, figsize=(18, 14))
        fig.suptitle('VANET Attack Pattern Analysis', fontsize=16, fontweight='bold')
        
        # 1. Attack distribution over time
        ax = axes[0, 0]
        attack_counts = self.df.groupby(['threat_type']).size()
        colors = ['green', 'red', 'orange', 'purple', 'yellow', 'brown']
        ax.pie(attack_counts.values, labels=attack_counts.index, autopct='%1.1f%%', 
               colors=colors[:len(attack_counts)])
        ax.set_title('Attack Type Distribution')
        
        # 2. Packet loss rate by attack type
        ax = axes[0, 1]
        threat_types = self.df['threat_type'].unique()
        packet_loss_data = [self.df[self.df['threat_type'] == t]['packet_loss_rate'].dropna() 
                           for t in threat_types]
        bp = ax.boxplot(packet_loss_data, labels=threat_types)
        ax.set_xlabel('Threat Type')
        ax.set_ylabel('Packet Loss Rate')
        ax.set_title('Packet Loss Rate by Attack Type')
        ax.grid(True, alpha=0.3)
        
        # 3. Latency distribution
        ax = axes[0, 2]
        for attack in self.df['threat_type'].unique():
            data = self.df[self.df['threat_type'] == attack]['latency']
            ax.hist(data, alpha=0.5, label=f'Type {attack}', bins=30)
        ax.set_xlabel('Latency (ms)')
        ax.set_ylabel('Frequency')
        ax.set_title('Latency Distribution by Attack Type')
        ax.legend()
        
        # 4. Signal strength patterns
        ax = axes[1, 0]
        signal_data = []
        labels = []
        for threat in threat_types:
            threat_data = self.df[self.df['threat_type'] == threat]['signal_strength']
            signal_data.append([threat_data.mean(), threat_data.std()])
            labels.append(f'Type {threat}')
        
        x = np.arange(len(labels))
        width = 0.35
        bars1 = ax.bar(x - width/2, [d[0] for d in signal_data], width, label='Mean')
        bars2 = ax.bar(x + width/2, [d[1] for d in signal_data], width, label='Std Dev')
        
        ax.set_xlabel('Threat Type')
        ax.set_ylabel('Signal Strength (dBm)')
        ax.set_title('Signal Strength Statistics')
        ax.set_xticks(x)
        ax.set_xticklabels(labels)
        ax.legend()
        
        # 5. Speed anomalies
        ax = axes[1, 1]
        normal_speed = self.df[self.df['threat_type'] == 0]['speed']
        attack_speed = self.df[self.df['threat_type'] != 0]['speed']
        
        if len(normal_speed) > 0 and len(attack_speed) > 0:
            ax.violinplot([normal_speed.dropna(), attack_speed.dropna()], 
                          positions=[0, 1], showmeans=True)
            ax.set_xticks([0, 1])
            ax.set_xticklabels(['Normal', 'Attack'])
            ax.set_ylabel('Speed (km/h)')
            ax.set_title('Speed Distribution Comparison')
        
        # 6. Data volume analysis
        ax = axes[1, 2]
        data_volume_data = [self.df[self.df['threat_type'] == t]['data_volume'].dropna() 
                            for t in threat_types]
        bp = ax.boxplot(data_volume_data, labels=threat_types)
        ax.set_xlabel('Threat Type')
        ax.set_ylabel('Data Volume')
        ax.set_title('Data Volume by Attack Type')
        ax.grid(True, alpha=0.3)
        
        # 7. Message frequency patterns - FIXED
        ax = axes[2, 0]
        # Create a grouped bar chart instead of pivot table
        msg_freq_data = self.df.groupby(['threat_type', 'message_frequency']).size().unstack(fill_value=0)
        if not msg_freq_data.empty:
            msg_freq_data.plot(kind='bar', stacked=True, ax=ax)
            ax.set_xlabel('Threat Type')
            ax.set_ylabel('Count')
            ax.set_title('Message Frequency Distribution by Threat Type')
            ax.legend(title='Msg Freq', bbox_to_anchor=(1.05, 1), loc='upper left')
        else:
            # Alternative: show mean message frequency per threat type
            mean_freq = self.df.groupby('threat_type')['message_frequency'].mean()
            mean_freq.plot(kind='bar', ax=ax, color='steelblue')
            ax.set_xlabel('Threat Type')
            ax.set_ylabel('Mean Message Frequency')
            ax.set_title('Average Message Frequency by Threat Type')
        
        plt.setp(ax.xaxis.get_majorticklabels(), rotation=0)
        
        # 8. Correlation heatmap for attacks
        ax = axes[2, 1]
        attack_data = self.df[self.df['threat_type'] != 0]
        numeric_cols = ['packet_loss_rate', 'latency', 'signal_strength', 
                       'data_volume', 'speed', 'RSU_distance']
        numeric_cols = [col for col in numeric_cols if col in attack_data.columns]
        
        if len(numeric_cols) > 0:
            corr_matrix = attack_data[numeric_cols].corr()
            sns.heatmap(corr_matrix, annot=True, fmt='.2f', cmap='coolwarm', 
                       center=0, ax=ax, cbar_kws={'label': 'Correlation'})
            ax.set_title('Feature Correlation in Attack Traffic')
        
        # 9. Temporal attack intensity
        ax = axes[2, 2]
        if 'timestamp' in self.df.columns:
            # Convert timestamp if needed
            temp_df = self.df.copy()
            temp_df['timestamp'] = pd.to_datetime(temp_df['timestamp'])
            
            # Group by 1-second windows
            temp_df['time_window'] = temp_df['timestamp'].dt.floor('1S')
            attack_intensity = temp_df[temp_df['threat_type'] != 0].groupby('time_window').size()
            
            if len(attack_intensity) > 0:
                # Limit to first 100 time windows for clarity
                plot_data = attack_intensity.head(100)
                ax.plot(range(len(plot_data)), plot_data.values, 'r-', linewidth=2)
                ax.fill_between(range(len(plot_data)), plot_data.values, alpha=0.3, color='red')
                ax.set_xlabel('Time Window (seconds)')
                ax.set_ylabel('Attack Count')
                ax.set_title('Attack Intensity Over Time (First 100 seconds)')
                ax.grid(True, alpha=0.3)
        
        plt.tight_layout()
        plt.savefig('vanet_attack_patterns.png', dpi=300, bbox_inches='tight')
        plt.show()
        
        print("\nVisualization saved as 'vanet_attack_patterns.png'")
    
    def generate_report(self):
        """Generate comprehensive analysis report"""
        
        print("\n" + "="*60)
        print("VANET ATTACK PATTERN ANALYSIS REPORT")
        print("="*60)
        
        # Basic statistics
        print(f"\nDataset Overview:")
        print(f"Total samples: {len(self.df)}")
        print(f"Normal traffic: {(self.df['threat_type'] == 0).sum()} ({100*(self.df['threat_type'] == 0).sum()/len(self.df):.1f}%)")
        print(f"Attack traffic: {(self.df['threat_type'] != 0).sum()} ({100*(self.df['threat_type'] != 0).sum()/len(self.df):.1f}%)")
        
        # Attack type breakdown
        print(f"\nAttack Type Breakdown:")
        for attack_type in self.df['threat_type'].unique():
            if attack_type != 0:
                count = (self.df['threat_type'] == attack_type).sum()
                print(f"  Type {attack_type}: {count} samples ({100*count/len(self.df):.2f}%)")
        
        # Network characteristics
        print(f"\nNetwork Impact by Attack Type:")
        results = self.analyze_network_characteristics()
        
        for attack_type, metrics in results.items():
            if attack_type == 0:
                print(f"\nNormal Traffic Baseline:")
            else:
                print(f"\nAttack Type {attack_type}:")
            
            for metric, values in metrics.items():
                if 'mean' in values:
                    print(f"  {metric}:")
                    print(f"    Mean: {values['mean']:.3f}")
                    print(f"    Median: {values['median']:.3f}")
                    print(f"    Std Dev: {values['std']:.3f}")
        
        # Attack signatures
        print(f"\nAttack Signatures (vs Normal Traffic):")
        signatures = self.detect_attack_signatures()
        
        for attack_type, signature in signatures.items():
            if signature:
                print(f"\nAttack Type {attack_type} Signatures:")
                for feature, stats in signature.items():
                    if stats['significant']:
                        print(f"  {feature}: {stats['ratio']:.2f}x normal")
        
        # Detection recommendations
        print(f"\n" + "="*60)
        print("DETECTION RECOMMENDATIONS:")
        print("="*60)
        
        print("\n1. Sybil Attack Detection:")
        print("   - Monitor for multiple IDs from same location")
        print("   - Check for synchronized message patterns")
        print("   - Analyze signal strength consistency")
        
        print("\n2. DoS Attack Detection:")
        print("   - Set threshold for packet loss rate > 0.8")
        print("   - Monitor message frequency > 40/sec")
        print("   - Track latency spikes > 70ms")
        
        print("\n3. False Data Injection Detection:")
        print("   - Validate speed range (30-120 km/h)")
        print("   - Check position consistency")
        print("   - Verify acceleration limits (±5 m/s²)")

def main():
    # Load the dataset (use your actual dataset file)
    try:
        df = pd.read_csv('vanet_dataset.csv')
    except:
        print("Dataset file not found. Please run the generator first.")
        return
    
    # Initialize analyzer
    analyzer = AttackPatternAnalyzer(df)
    
    # Run analysis
    analyzer.analyze_temporal_patterns()
    analyzer.generate_report()
    
    # Create visualizations with error handling
    try:
        analyzer.plot_attack_patterns()
    except Exception as e:
        print(f"Error in plotting: {e}")
        print("Attempting alternative visualization...")
    
    print("\n" + "="*60)
    print("Analysis complete!")
    print("="*60)

if __name__ == "__main__":
    main()