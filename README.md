# PCAP / Network Analysis Tool (Python)

A menu-driven terminal tool for analysing `.pcap` captures.  
It parses packets, builds tabular summaries, computes simple statistics, and generates visualisations (line chart & communication graph).

---

## Features

- **Open & parse PCAP** (Ethernet/IP) and cache key fields per packet for fast queries.
- **Interactive menu with 7 options** to explore the capture using the information stored on load. (Menu invoked after the file check.)
- **Packet table output** (pretty-printed) using `tabulate`.
- **Statistics**: calculates a mean/average of packets per interval. (Used in the line-chart overlay.)  
- **Visualisations**:
  - **Line chart**: number of packets per interval with mean baseline (Matplotlib).  
    ![Packets line chart](evidence/evidence-packet-analysis_line_chart.png)
  - **Network graph**: IP-to-IP communication graph (NetworkX).  
    ![Network graph](evidence/evidence-packet-analysis_net_graph.png)
- **Dependency map**: module-level diagram of call flow.  
  ![Dependency diagram](evidence/dependency_diagram.jpeg)

> Core libraries used: `dpkt`, `socket`, `tabulate`, `networkx`, `matplotlib`.

---

## Project structure
