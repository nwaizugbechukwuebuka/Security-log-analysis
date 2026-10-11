# Security Log Analysis and Incident Timeline

**A Python-based cybersecurity project for detecting suspicious authentication activity and investigating potential supplier payment fraud.**

**Author:** Tobiloba Nwaizugbe

**Project Category:** Cybersecurity | Security Engineering | Security Operations

**Technologies:** Python, Pandas, Pytest, Git

**Status:** Educational proof of concept

---

## Project Overview

How can a security analyst identify suspicious account activity before it leads to financial loss?

This project demonstrates how Python can be used to analyze security logs, identify unusual authentication patterns, and reconstruct a potential security incident.

The simulated scenario involves an employee account experiencing repeated failed login attempts, followed by a successful login, supplier-record access, and a change to sensitive banking information.

Using Python and Pandas, the project processes security events, calculates investigation metrics, identifies suspicious sequences, and produces a chronological incident timeline.

The goal is to demonstrate how structured security data can support **incident investigation, risk identification, and evidence-based security decisions**.

## Business Problem

Unauthorized changes to supplier banking information can expose an organization to payment diversion and financial fraud.

Security teams need to identify warning signs, understand the sequence of events, and determine whether sensitive actions were authorized.

This project addresses that challenge by demonstrating how an analyst can:

* Identify repeated failed login attempts.
* Detect successful authentication following repeated failures.
* Correlate suspicious login activity with sensitive supplier-record changes.
* Measure the time between authentication and sensitive activity.
* Reconstruct events into a chronological timeline.
* Generate findings to guide further investigation.

The analysis identifies indicators that warrant investigation; it does not automatically establish that an account has been compromised.

## Key Findings

The analysis of the six-event sample dataset produces the following results:

| Investigation Metric                                        |     Result |
| ----------------------------------------------------------- | ---------: |
| Security events analyzed                                    |          6 |
| Total login attempts                                        |          4 |
| Failed login attempts                                       |          2 |
| Successful login attempts                                   |          2 |
| Failed-login rate                                           |        50% |
| Distinct source IP addresses                                |          2 |
| Successful login following repeated failures                |   Detected |
| Sensitive banking-detail modifications                      |          1 |
| Time between suspicious successful login and banking change |  6 minutes |
| Observed activity window                                    | 10 minutes |

### What These Results Mean

Three observations are particularly important:

1. **Repeated authentication failures:** Two failed login attempts from the same source IP were followed by a successful login.
2. **Sensitive information accessed:** The account viewed a supplier record three minutes after the successful login.
3. **Banking information modified:** The account modified supplier banking details six minutes after the successful login.

Together, these observations form a suspicious sequence that a security analyst should investigate further.

## Technical Implementation

### 1. Security Log Processing

The project uses Python and Pandas to load, validate, organize, and analyze structured security events.

The analysis processes fields such as:

* Timestamp
* User
* Event
* Source IP
* Result

### 2. Authentication Analysis

The project examines authentication events to identify repeated failures and successful logins that follow suspicious patterns.

This demonstrates foundational security monitoring techniques used to investigate potentially compromised accounts.

### 3. Event Correlation

The analysis correlates events using available information, including user accounts, source IP addresses, and timestamps.

It examines the relationship between authentication activity and subsequent sensitive supplier-record operations.

### 4. Incident Timeline Reconstruction

Security events are ordered chronologically to provide a clear sequence of activity.

The resulting timeline helps an investigator understand what happened, when it happened, and which events require additional scrutiny.

### 5. Investigation Metrics

The project calculates the observed activity window using the earliest and latest timestamps.

It also reports investigation metrics such as the number of records analyzed and the elapsed time between relevant events.

### 6. Automated Testing

Pytest is used to verify the analysis logic and important expected behaviours.

Automated tests help ensure that the application processes sample logs consistently and handles relevant validation scenarios.

## Sample Incident Timeline

| Time  | Event                  | Security Significance                              |
| ----- | ---------------------- | -------------------------------------------------- |
| 09:00 | Successful login       | Initial authentication from `10.0.0.12`.           |
| 09:02 | Failed login           | First failed attempt from `203.0.113.25`.          |
| 09:03 | Failed login           | Second failed attempt from the same source IP.     |
| 09:04 | Successful login       | Authentication succeeds after repeated failures.   |
| 09:07 | Supplier record viewed | Supplier information is accessed.                  |
| 09:10 | Bank details modified  | Sensitive supplier banking information is changed. |

**Investigation outcome:** The sequence warrants further review to establish whether the successful login and banking modification were legitimate.

## Recommended Investigation Actions

Based on the simulated findings, a security analyst could:

1. Verify whether the successful login was authorized.
2. Review authentication records and multifactor authentication results.
3. Confirm whether the supplier banking change was approved.
4. Compare the original and modified banking details.
5. Review related payment creation, approval, and execution records.
6. Preserve relevant logs and audit evidence.
7. Follow the organization's incident-response procedures if unauthorized activity is confirmed or actively suspected.

These recommendations demonstrate how automated log analysis can support, rather than replace, an analyst's investigation.

## Technology Stack

| Technology     | Application                                              |
| -------------- | -------------------------------------------------------- |
| Python         | Analysis logic and automation                            |
| Pandas         | Log processing, data aggregation, and timestamp analysis |
| Pytest         | Automated testing                                        |
| Git and GitHub | Version control and project presentation                 |

## Project Structure

```text
Security-log-analysis/
├── data/
│   └── sample_security_logs.csv
├── reports/
│   └── incident_timeline.csv
├── src/
│   └── log_analysis.py
├── tests/
│   └── test_log_analysis.py
├── README.md
├── requirements.txt
└── .gitignore
```

* `data/` — Contains the simulated security logs.
* `src/` — Contains the log analysis and detection logic.
* `tests/` — Contains automated tests.
* `reports/` — Stores the generated incident timeline.
* `requirements.txt` — Defines the Python dependencies.

## How to Run the Project

### Prerequisites

* Python 3.10 or later
* pip

### 1. Clone the Repository

Replace the placeholder with the actual GitHub repository URL.

```powershell
git clone <your-repository-url>
cd Security-log-analysis
```

### 2. Create a Virtual Environment

```powershell
python -m venv .venv
```

Activate it in Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

### 3. Install Dependencies

```powershell
python -m pip install -r requirements.txt
```

### 4. Run the Analysis

```powershell
python -m src.log_analysis
```

The application processes the sample logs, calculates investigation metrics, identifies relevant suspicious patterns, and generates the incident timeline.

### 5. Run the Tests

```powershell
python -m pytest -q
```

## Skills Demonstrated

**Cybersecurity**

* Security log analysis
* Authentication anomaly detection
* Incident investigation fundamentals
* Security event correlation
* Sensitive-record activity analysis
* Incident timeline reconstruction

**Data Analysis and Programming**

* Python programming
* Pandas data processing
* Timestamp calculations
* Data validation and aggregation
* Automated testing with Pytest

**Professional Skills**

* Evidence-based problem-solving
* Structured incident documentation
* Risk identification
* Analytical thinking
* Translating technical findings into actionable investigation steps

## Limitations and Future Development

This project uses a small, simulated dataset and is intended for learning and portfolio demonstration.

The current analysis does not independently verify whether an account has been compromised. It also lacks session identifiers, device information, multifactor authentication outcomes, and a historical baseline of normal user behaviour.

Potential future enhancements include:

* Support for additional authentication log formats.
* Integration with Windows and Linux security logs.
* Configurable detection thresholds and risk scoring.
* More advanced event correlation using session and device identifiers.
* Integration with a SIEM or security incident management workflow.
* Real-time log ingestion and alerting.
* Expanded automated tests and investigation reporting.

These improvements would help move the project towards a more comprehensive security monitoring and incident investigation solution.

## Conclusion

The **Security Log Analysis and Incident Timeline** project demonstrates how Python-based analysis can help identify suspicious authentication patterns, correlate security events with sensitive business operations, and organize findings into an actionable investigation timeline.

By combining security concepts with data analysis and automated testing, the project provides a practical demonstration of foundational skills relevant to cybersecurity, security operations, and junior security engineering roles.

**Repository focus:** Security log analysis, authentication monitoring, incident investigation, and Python automation.


[![GitHub](https://img.shields.io/badge/GitHub-Project-181717.svg?style=flat\&logo=github)](https://github.com/nwaizugbechukwuebuka/AI-Factory-Operations-Agent)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-0077b5.svg?style=flat\&logo=linkedin)](https://www.linkedin.com/in/chukwuebuka-tobiloba-nwaizugbe/)
[![Discord](https://img.shields.io/badge/Join%20us%20on-Discord-5865F2?logo=discord\&logoColor=white\&style=for-the-badge)](https://discord.gg/deepworksociety)

</div>
