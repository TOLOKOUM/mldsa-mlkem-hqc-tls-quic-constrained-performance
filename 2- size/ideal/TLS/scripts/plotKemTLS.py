import csv
import os
import argparse
import matplotlib.pyplot as plt
import numpy as np

def plot_csv(filename):
    # Get signature algorithm name from filename
    sig_alg = os.path.splitext(os.path.basename(filename))[0]

    if sig_alg.endswith('_tls_size'):
        sig_alg = sig_alg[:-len('_tls_size')]

    # Prepare data
    kems = []
    tcp_kb = []
    tls_kb = []

    # Read CSV
    with open(filename, mode='r', newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            kems.append(row['KEM_ALG'])
            tcp_kb.append(int(row['Suma_TCP']) / 1024)
            tls_kb.append(int(row['Suma_TLS']) / 1024)

    # Adjust bar width and separation
    bar_width = 0.7  # Adjust this value for more/less separation
    index = np.arange(len(kems))  # X-axis indices for bars

    # Plot stacked bar chart with separated bars
    plt.figure(figsize=(9, 6))
    
    plt.bar(index + bar_width, tcp_kb, label='TCP handshake', color='#004c6d', alpha=0.7, width=bar_width)
    plt.bar(index + bar_width, tls_kb, bottom=tcp_kb, label='TLSv1.3', color='#004c6d', width=bar_width)

    # Añadir etiquetas dentro de las barras TCP y TLS
    for i in range(len(kems)):
        # Etiqueta dentro de la parte TCP
        if tcp_kb[i] > 0:
            if tcp_kb[i] < 1:
                # Valor muy pequeño → se muestra arriba
                plt.text(index[i] + bar_width, tcp_kb[i] / 2 , f"{tcp_kb[i]:.1f}",
                         ha='center', va='bottom', fontsize=16, color='white', fontweight='bold')
            

        # Etiqueta dentro de la parte TLS (por encima del TCP)
        if tls_kb[i] > 0:
            y_pos = tcp_kb[i] + (tls_kb[i] / 2)
            plt.text(index[i] + bar_width, y_pos, f"{tls_kb[i]:.1f}",
                     ha='center', va='center', fontsize=16, color='white', fontweight='bold')

        total = tcp_kb[i] + tls_kb[i]
        plt.text(index[i] + bar_width, total , f"{total:.1f}",
                 ha='center', va='bottom', fontsize=16, color='blue', fontweight='bold')       
        
    # Set labels, title, and adjust font size
    plt.ylabel('Total Size (KB)', fontsize=16)
    #plt.title(f'Total traffic size by KEM for signature algorithm {sig_alg}', fontsize=16)
    plt.tick_params(axis='y', labelsize=16)

    etiquetas1 = ['P-256', 'x25519', 'P-256\nmlkem512', 'x25519\nmlkem512', 'mlkem512']
    etiquetas3 = ['P-384', 'x448', 'P-384\nmlkem768', 'x448\nmlkem768', 'mlkem768']
    etiquetas5 = ['P-521', 'P-521\nmlkem1024', 'mlkem1024']
    

    if sig_alg == 'ed25519':
        etiquetas = etiquetas1
    elif sig_alg == 'secp384r1':
        etiquetas = etiquetas3
    elif sig_alg == 'secp521r1':
        etiquetas = etiquetas5
    
    plt.xticks(index + bar_width, labels=etiquetas, fontsize=18)
    plt.yticks(fontsize=20)

    # Add grid for better readability
    plt.grid(axis='y', linestyle='--', alpha=0.7)

    # Add legend with title and adjusted font size
    plt.legend(title='Protocols', fontsize=14, title_fontsize=16, loc='best', ncol=1)

    plt.tight_layout()

    # Save and show the plot
    output_file = f"{sig_alg}_TLS_size.pdf"
    plt.savefig(output_file)
    print(f"Plot saved as {output_file}")
    #plt.show()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Generate stacked bar chart from a signature algorithm CSV')
    parser.add_argument('csv_file', help='Path to the signature CSV file (e.g., ed25519.csv)')
    args = parser.parse_args()

    plot_csv(args.csv_file)

