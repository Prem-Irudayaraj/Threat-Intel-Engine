# Threat Intelligence Correlation Engine

## Overview

The Threat Intelligence Correlation Engine is a Python-based security analytics tool designed to simulate core SOC (Security Operations Center) detection workflows.  

This project ingests network logs, authentication logs, and simulated cloud logs, then correlates them against a structured threat intelligence feed containing Indicators of Compromise (IOCs) such as malicious IP addresses, domains, and file hashes.

The engine generates structured alert reports and an executive risk summary, replicating real-world blue team monitoring and threat detection processes.

---

## Features

- IOC Correlation (IP, Domain, Hash)
- CSV & JSON Log Parsing
- Network Log Analysis
- Authentication Log Analysis
- Cloud Log Analysis (Simulated AWS/Azure style logs)
- Risk Scoring Engine
- Automated Alert Report Generation
- Executive Summary Output
- Modular & Expandable Architecture

---

## Project Structure
