import csv
import os
import argparse
import matplotlib.pyplot as plt
import numpy as np

def plot_csv(filename):
    # Get signature algorithm name from filename
    sig_alg = os.path.splitext(os.path.basename(filename))[0]

    # Prepare data
    kems = []
    tls_kb = []

    # Read CSV
    with open(filename, mode='r', newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            kems.append(row['KEM_ALG'])
            tls_kb.append(int(row['Suma_QUIC']) / 1024)

    # Adjust bar width and separation
    bar_width = 0.7  # Adjust this value for more/less separation
    index = np.arange(len(kems))  # X-axis indices for bars

    # Plot stacked bar chart with separated bars
    plt.figure(figsize=(10, 6))
    
    plt.bar(index + bar_width, tls_kb, label='QUIC (KB)', color='#004c6d', width=bar_width)

    for i, value in enumerate(tls_kb):
        plt.text(index[i] + bar_width, value - (max(tls_kb) * 0.05),  # Ajusta 0.05 según altura
             f"{value:.1f}", ha='center', va='top', fontsize=12, color='white', fontweight='bold')
    
    # Set labels, title, and adjust font size
    plt.ylabel('Total Size (KB)', fontsize=16)
    plt.title(f'Total traffic size by KEM for signature algorithm {sig_alg}', fontsize=16)
    plt.xticks(index + bar_width , kems, fontsize=13)
    plt.tick_params(axis='y', labelsize=16)

    # Add grid for better readability
    plt.grid(axis='y', linestyle='--', alpha=0.7)

    # Add legend with title and adjusted font size
    #plt.legend(title='KEM Algorithms', fontsize=10, title_fontsize=12, loc='best', ncol=2)

    plt.tight_layout()

    # Save and show the plot
    output_file = f"{sig_alg}_QUIC_size.pdf"
    plt.savefig(output_file)
    print(f"Plot saved as {output_file}")
    plt.show()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Generate stacked bar chart from a signature algorithm CSV')
    parser.add_argument('csv_file', help='Path to the signature CSV file (e.g., ed25519.csv)')
    args = parser.parse_args()

    plot_csv(args.csv_file)

