# LLM-Threat-Intel-Fusion

LLM-Threat-Intel-Fusion is an innovative cybersecurity project that fuses Large Language Model (LLM) analysis with structured threat intelligence (MITRE ATT&CK, Sigma, and OSINT feeds) to provide advanced, context-aware detection and response capabilities.

## Description

Modern cybersecurity operations require rapid, intelligent analysis of alerts, logs, and threat intelligence. LLM-Threat-Intel-Fusion leverages the power and flexibility of LLMs to contextualize security alerts, map them to MITRE ATT&CK techniques, correlate with Sigma rules, and enrich with OSINT indicators in real time. The result is a system that not only detects threats, but also suggests likely threat actors, attack patterns, and tailored mitigation strategies.

## Features

- **LLM-Driven Alert Contextualization:** Uses OpenAI’s LLMs to analyze security alerts and provide detailed, actionable insights.
- **MITRE ATT&CK Integration:** Maps events and alerts to relevant ATT&CK techniques and provides summaries for rapid triage.
- **Sigma Rule Fusion:** Supports future integration with Sigma rules for log/event pattern detection.
- **OSINT Enrichment:** Pulls indicators from public threat feeds for enhanced context and threat validation.
- **Adaptation & Updating:** Designed to periodically update intelligence sources and adapt to new threats.

## Quick Start

1. Clone the repository:
    ```bash
    git clone https://github.com/SecureVortex/LLM-Threat-Intel-Fusion.git
    cd LLM-Threat-Intel-Fusion
    ```
2. Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```
3. Set your OpenAI API key in the environment or directly in the script.
4. Run the main script:
    ```bash
    python llm_threat_intel_context.py
    ```

## Example Use Case

- The script fetches recent alerts, MITRE ATT&CK data, Sigma rules (placeholder), and OSINT feeds.
- It contextualizes each alert using the LLM, suggesting likely attack techniques, threat actors, and recommended mitigations.

## Requirements

- Python 3.8+
- `openai`, `requests` Python packages
- OpenAI API key

## License

See [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! Please open an issue or PR.

## Disclaimer

This project is for research and educational purposes. Use at your own risk.
