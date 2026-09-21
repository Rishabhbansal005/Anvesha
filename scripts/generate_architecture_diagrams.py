"""
Generates high-resolution flowchart diagrams for the ANVESH Architecture & Technical Audit.
"""
import os
import matplotlib.pyplot as plt
import matplotlib.patches as patches

OUTPUT_DIR = r"C:\Users\Ongkar\Desktop\Avnesh\Anvesha-main\Anvesha-main\docs\screenshots"
os.makedirs(OUTPUT_DIR, exist_ok=True)

def generate_master_flowchart():
    fig, ax = plt.subplots(figsize=(12, 7.5), dpi=300)
    ax.set_facecolor("#0F172A")
    fig.patch.set_facecolor("#0F172A")
    ax.axis("off")

    def draw_box(x, y, w, h, title, subtitle, bg_color, border_color, text_color="#FFFFFF"):
        rect = patches.FancyBboxPatch(
            (x, y), w, h, boxstyle="round,pad=0.08,rounding_size=0.15",
            facecolor=bg_color, edgecolor=border_color, linewidth=1.5
        )
        ax.add_patch(rect)
        ax.text(x + w/2, y + h*0.62, title, ha="center", va="center",
                fontsize=9.5, fontweight="bold", color=text_color)
        ax.text(x + w/2, y + h*0.30, subtitle, ha="center", va="center",
                fontsize=7.5, color="#94A3B8")

    def draw_arrow(x1, y1, x2, y2, label="", color="#38BDF8"):
        ax.annotate(
            "", xy=(x2, y2), xytext=(x1, y1),
            arrowprops=dict(arrowstyle="-|>", color=color, lw=1.8, mutation_scale=14)
        )
        if label:
            ax.text((x1+x2)/2, (y1+y2)/2 + 0.12, label, ha="center", va="bottom",
                    fontsize=7, color="#E2E8F0", fontweight="bold")

    # Title
    ax.text(6, 7.1, "ANVESH — END-TO-END SYSTEM ARCHITECTURE FLOWCHART",
            ha="center", va="center", fontsize=14, fontweight="bold", color="#F8FAFC")
    ax.text(6, 6.75, "Dual-Pillar Ingestion, Multi-Tier ML Inference, Signal Fusion & Forensic Adjudication",
            ha="center", va="center", fontsize=8.5, color="#94A3B8")

    # Raw Inputs (Left)
    draw_box(0.5, 4.8, 2.2, 1.2, "Raw RFC-822 Email", ".eml File Ingestion", "#1E293B", "#38BDF8")
    draw_box(0.5, 1.8, 2.2, 1.2, "Live Network Wire", "MediaTek Wi-Fi / Eth (Npcap)", "#1E293B", "#10B981")

    # Preprocessing & Dissection (Col 2)
    draw_box(3.4, 4.8, 2.4, 1.2, "MIME & Hop Traversal", "SHA-256 Digest + BGP/Tor", "#1E293B", "#6366F1")
    draw_box(3.4, 1.8, 2.4, 1.2, "Scapy Dissector", "5-Tuple Flow Aggregator", "#1E293B", "#059669")

    # AI & ML Engines (Col 3)
    draw_box(6.5, 5.4, 2.5, 1.0, "Models 1 & 2 (NLP & BEC)", "10k Phish + 5k BEC Features", "#1E293B", "#EC4899")
    draw_box(6.5, 4.1, 2.5, 1.0, "Models 3A & 3B", "Display Name & Typosquatting", "#1E293B", "#F59E0B")
    draw_box(6.5, 1.8, 2.5, 1.2, "Model 4/5 (Random Forest)", "41-Feature NSL-KDD Benchmark", "#1E293B", "#10B981")

    # Signal Fusion & Decision (Col 4)
    draw_box(9.7, 3.8, 2.1, 2.0, "Signal Fusion Engine", "Cross-Corroboration\n0-100 Threat Score\nEthical Boundary Check", "#1E293B", "#8B5CF6")
    draw_box(9.7, 1.4, 2.1, 1.6, "Forensic Deliverables", "Court PDF Dossier\nWireshark PCAP\nSOC Alert Queue", "#1E293B", "#38BDF8")

    # Connectors
    draw_arrow(2.7, 5.4, 3.4, 5.4, "Upload")
    draw_arrow(2.7, 2.4, 3.4, 2.4, "Raw Packets")

    draw_arrow(5.8, 5.6, 6.5, 5.9, "Clean Text")
    draw_arrow(5.8, 5.0, 6.5, 4.6, "Headers")
    draw_arrow(5.8, 2.4, 6.5, 2.4, "41 Features")

    draw_arrow(9.0, 5.9, 9.7, 5.3)
    draw_arrow(9.0, 4.6, 9.7, 4.8)
    draw_arrow(9.0, 2.4, 9.7, 2.2, "Anomaly Verdict")
    draw_arrow(10.75, 3.8, 10.75, 3.0, "Evidence")

    ax.set_xlim(0, 12.3)
    ax.set_ylim(0.8, 7.5)
    plt.tight_layout()
    output_path = os.path.join(OUTPUT_DIR, "anvesh_master_architecture_flowchart.png")
    plt.savefig(output_path, dpi=300, facecolor=fig.get_facecolor(), edgecolor='none')
    plt.close()
    print(f"[+] Master Flowchart saved: {output_path}")

def generate_network_flowchart():
    fig, ax = plt.subplots(figsize=(12, 6), dpi=300)
    ax.set_facecolor("#0F172A")
    fig.patch.set_facecolor("#0F172A")
    ax.axis("off")

    def draw_box(x, y, w, h, title, subtitle, bg_color, border_color):
        rect = patches.FancyBboxPatch(
            (x, y), w, h, boxstyle="round,pad=0.08,rounding_size=0.15",
            facecolor=bg_color, edgecolor=border_color, linewidth=1.5
        )
        ax.add_patch(rect)
        ax.text(x + w/2, y + h*0.62, title, ha="center", va="center",
                fontsize=9, fontweight="bold", color="#FFFFFF")
        ax.text(x + w/2, y + h*0.30, subtitle, ha="center", va="center",
                fontsize=7.2, color="#94A3B8")

    def draw_arrow(x1, y1, x2, y2, label=""):
        ax.annotate(
            "", xy=(x2, y2), xytext=(x1, y1),
            arrowprops=dict(arrowstyle="-|>", color="#10B981", lw=1.8, mutation_scale=14)
        )
        if label:
            ax.text((x1+x2)/2, (y1+y2)/2 + 0.12, label, ha="center", va="bottom",
                    fontsize=7, color="#E2E8F0", fontweight="bold")

    ax.text(6, 5.5, "ENGINE 5: REAL-TIME NETWORK THREAT DETECTION (NDR) PIPELINE",
            ha="center", va="center", fontsize=13, fontweight="bold", color="#F8FAFC")
    ax.text(6, 5.15, "Kernel Hooking (Npcap) ➔ Scapy Dissection ➔ 41-Feature NSL-KDD ML ➔ PCAP Export",
            ha="center", va="center", fontsize=8, color="#94A3B8")

    draw_box(0.5, 2.5, 2.0, 1.6, "1. Network Card", "MediaTek Wi-Fi / Eth\nPassive Npcap Hook", "#1E293B", "#38BDF8")
    draw_box(2.9, 2.5, 2.0, 1.6, "2. Scapy Sniffer", "Decodes IP/TCP/UDP\nFilters Noise/Miniports", "#1E293B", "#6366F1")
    draw_box(5.3, 2.5, 2.0, 1.6, "3. Flow Aggregator", "5-Tuple Session Table\nByte/Duration Ratios", "#1E293B", "#F59E0B")
    draw_box(7.7, 2.5, 2.0, 1.6, "4. Model 4/5 (RF)", "41-Feature NSL-KDD\nAnomaly Classification", "#1E293B", "#EC4899")
    draw_box(10.1, 2.5, 1.8, 1.6, "5. SOC Output", "Live Streaming Table\nWireshark .pcap Export", "#1E293B", "#10B981")

    draw_arrow(2.5, 3.3, 2.9, 3.3, "Raw Frames")
    draw_arrow(4.9, 3.3, 5.3, 3.3, "Parsed Pkts")
    draw_arrow(7.3, 3.3, 7.7, 3.3, "Flow Vectors")
    draw_arrow(9.7, 3.3, 10.1, 3.3, "Verdicts")

    # Detail sub-cards
    draw_box(0.5, 0.7, 4.4, 1.2, "Passive Wire Protection", "Does NOT broadcast or inject packets; 100% safe", "#111827", "#334155")
    draw_box(5.3, 0.7, 6.6, 1.2, "Model 4/5 Attributes (41 NSL-KDD Features)", "9 Basic Connection + 13 Host Privilege + 9 Time Traffic + 10 Host Count", "#111827", "#334155")

    ax.set_xlim(0, 12.3)
    ax.set_ylim(0.4, 5.8)
    plt.tight_layout()
    output_path = os.path.join(OUTPUT_DIR, "anvesh_dual_pipeline_flowchart.png")
    plt.savefig(output_path, dpi=300, facecolor=fig.get_facecolor(), edgecolor='none')
    plt.close()
    print(f"[+] Network Flowchart saved: {output_path}")

if __name__ == "__main__":
    generate_master_flowchart()
    generate_network_flowchart()
