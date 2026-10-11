# Security Log Analysis and Incident Timeline

**A Python-based cybersecurity project for identifying suspicious authentication activity and investigating potential supplier payment fraud.**

|                  |                                                                                 |
| ---------------- | ------------------------------------------------------------------------------- |
| **Author**       | Tobiloba Nwaizugbe                                                              |
| **Category**     | Cybersecurity, Security Operations, Security Engineering                        |
| **Technologies** | Python, Pandas, Pytest, Git                                                     |
| **Project Type** | Educational Proof of Concept                                                    |
| **Repository**   | [View on GitHub](https://github.com/nwaizugbechukwuebuka/Security-log-analysis) |

---

## 1. Project Overview

How can an organization identify suspicious account activity before it leads to financial loss?

This project demonstrates how Python can help security analysts investigate unusual authentication patterns and identify potentially unauthorized changes to sensitive business information.

Using a simulated supplier payment fraud scenario, the application processes security logs, analyzes authentication events, calculates investigation metrics, and reconstructs activity into a chronological incident timeline.

The objective is to demonstrate how structured security data can support incident investigation, risk identification, and evidence-based decision-making.

## 2. Business Problem

Unauthorized modifications to supplier banking information can expose organizations to payment diversion and financial fraud.

Security analysts need to recognize suspicious activity, understand the sequence of events, and determine whether sensitive actions were legitimate.

This project explores how automated log analysis can help address these challenges by:

* Identifying repeated failed login attempts.
* Examining successful authentication following failed attempts.
* Correlating authentication activity with sensitive supplier-record operations.
* Measuring the time between suspicious authentication and subsequent activity.
* Reconstructing events into a chronological investigation timeline.
* Producing findings that guide further investigation.

**Business value:** The analysis demonstrates how security teams can organize technical evidence to investigate potentially unauthorized activity and prioritize their response.

## 3. Key Findings

The simulated dataset contains six security events involving authentication and supplier-record activity.

The reported analysis produces the following results:

| Investigation Metric                                            |     Result |
| --------------------------------------------------------------- | ---------: |
| Security events analyzed                                        |          6 |
| Total login attempts                                            |          4 |
| Failed login attempts                                           |          2 |
| Successful login attempts                                       |          2 |
| Failed-login rate                                               |        50% |
| Distinct source IP addresses                                    |          2 |
| Sensitive banking-detail modifications                          |          1 |
| Time from the suspicious successful login to the banking change |  6 minutes |
| Observed activity window                                        | 10 minutes |

*These figures describe the sample scenario and should be verified against the generated analysis output.*

### What the Findings Mean

Three observations warrant further investigation:

**1. Unusual authentication sequence**

Two failed login attempts from the same source IP were followed by a successful login. This pattern may warrant investigation to determine whether the authentication activity was legitimate.

**2. Access to supplier information**

The account viewed a supplier record three minutes after the successful login, establishing a temporal relationship between authentication and sensitive business activity.

**3. Modification of banking information**

The account modified supplier banking details six minutes after the successful login. This action is particularly relevant because unauthorized banking changes can create a risk of payment diversion.

**Investigation conclusion:** The observed sequence warrants further review, but the available evidence does not independently establish account compromise or confirmed financial fraud.

## 4. Technical Implementation

### Security Log Processing

Python and Pandas are used to load, organize, and analyze structured security events.

The analysis works with fields including timestamps, user accounts, event types, source IP addresses, and authentication results.

### Authentication Analysis

The application examines login attempts to identify repeated authentication failures and successful logins that follow suspicious patterns.

This demonstrates foundational security monitoring and authentication investigation techniques.

### Event Correlation

The analysis examines the chronological relationship between authentication events and subsequent supplier-record operations.

Available event attributes, including user accounts, source IP addresses, and timestamps, help organize activity for investigation.

### Incident Timeline Reconstruction

Events are arranged chronologically to provide a structured account of observed activity.

The resulting timeline helps an analyst understand what happened, when it happened, and which events require additional scrutiny.

### Investigation Metrics

The application calculates relevant investigation metrics, including the number of events analyzed, authentication statistics, the overall activity window, and elapsed time between selected events.

These measurements help turn raw log records into information that is easier to interpret and communicate.

### Automated Testing

Pytest is used to validate the analysis logic and expected application behaviour.

Automated tests support consistency and help identify defects when the implementation changes.

## 5. Sample Incident Timeline

The following timeline illustrates the simulated scenario.

| Time  | Event                    | Investigation Significance                           |
| ----- | ------------------------ | ---------------------------------------------------- |
| 09:00 | Successful login         | Initial authentication from `10.0.0.12`.             |
| 09:02 | Failed login             | First failed attempt from `203.0.113.25`.            |
| 09:03 | Failed login             | Second failed attempt from the same source IP.       |
| 09:04 | Successful login         | Authentication succeeds following repeated failures. |
| 09:07 | Supplier record viewed   | Supplier information is accessed.                    |
| 09:10 | Banking details modified | Sensitive supplier banking information is changed.   |

The IP addresses and events are illustrative and form part of a simulated dataset.

The timeline highlights the importance of correlating authentication activity with subsequent sensitive operations rather than investigating each event in isolation.

## 6. Recommended Investigation Actions

Based on the simulated findings, a security analyst could:

1. Verify whether the successful login was authorized.
2. Review authentication records and available multifactor authentication results.
3. Confirm whether the supplier banking change followed the organization's approval process.
4. Compare the original and modified banking information.
5. Review related payment creation, approval, and execution records.
6. Preserve relevant security logs and audit evidence.
7. Follow the organization's incident-response procedures if unauthorized activity is confirmed or actively suspected.

These recommendations illustrate how automated analysis can support an investigation without replacing analyst judgment.

## 7. Technology Stack

| Technology | Purpose                                              |
| ---------- | ---------------------------------------------------- |
| Python     | Security analysis logic and automation               |
| Pandas     | Data processing, aggregation, and timestamp analysis |
| Pytest     | Automated testing and validation                     |
| Git        | Source control and change tracking                   |
| GitHub     | Code hosting and project documentation               |

## 8. Project Structure

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

### Directory Overview

* `data/` — Contains the simulated security log dataset.
* `reports/` — Stores the generated incident timeline.
* `src/` — Contains the log processing and analysis logic.
* `tests/` — Contains automated tests.
* `requirements.txt` — Lists the Python dependencies.
* `.gitignore` — Specifies files and directories excluded from version control.

## 9. Getting Started

### Prerequisites

* Python 3.10 or later.
* pip.
* Git.

### Step 1: Clone the Repository

Open Windows PowerShell and run:

```powershell
git clone https://github.com/nwaizugbechukwuebuka/Security-log-analysis.git

cd Security-log-analysis
```

### Step 2: Create a Virtual Environment

```powershell
python -m venv .venv
```

Activate the environment:

```powershell
.\.venv\Scripts\Activate.ps1
```

### Step 3: Install Dependencies

```powershell
python -m pip install -r requirements.txt
```

### Step 4: Run the Analysis

```powershell
python -m src.log_analysis
```

The application should process the sample dataset, calculate investigation metrics, and generate the incident timeline.

The generated output depends on the implementation and the contents of the dataset.

### Step 5: Run the Automated Tests

```powershell
python -m pytest -v
```

This command runs the project's automated test suite and displays the results.

## 10. Skills Demonstrated

### Cybersecurity and Security Operations

* Security log analysis.
* Authentication anomaly investigation.
* Security event correlation.
* Incident timeline reconstruction.
* Sensitive-record activity analysis.
* Incident-response fundamentals.

### Programming and Data Analysis

* Python programming.
* Pandas data processing.
* Timestamp calculations.
* Data aggregation and validation.
* Automated testing with Pytest.
* Reproducible analysis workflows.

### Professional Capabilities

* Analytical thinking and problem-solving.
* Evidence-based decision-making.
* Structured technical documentation.
* Risk identification.
* Translating technical observations into actionable recommendations.

## 11. Limitations and Future Development

This project uses a small, simulated dataset and is intended for educational and portfolio purposes.

The current scenario does not establish whether the account was compromised or whether the banking change was fraudulent.

Additional evidence would be required to establish authorization, user intent, and the relationship between authentication and sensitive activity.

Potential future enhancements include:

* Support for Windows and Linux security log formats.
* Configurable detection thresholds and risk scoring.
* More advanced correlation using session identifiers and device information.
* Integration with a Security Information and Event Management (SIEM) platform.
* Automated alerting and investigation reporting.
* Expanded test coverage for missing data, duplicate events, and invalid timestamps.
* Integration with incident-response workflows.

These enhancements could extend the project into a more comprehensive security monitoring and investigation solution.

## 12. Conclusion

The **Security Log Analysis and Incident Timeline** project demonstrates how Python-based analysis can help identify suspicious authentication patterns, correlate security events with sensitive business operations, and organize findings into an investigation timeline.

By combining cybersecurity concepts, data analysis, and automated testing, the project provides practical evidence of skills relevant to entry-level cybersecurity, Security Operations Centre (SOC), and junior security engineering roles.

The project emphasizes an important principle of security investigation: **suspicious activity should be supported by evidence and investigated before conclusions are drawn.**

---

## Connect

[![GitHub](https://img.shields.io/badge/GitHub-Project-181717.svg?style=flat\&logo=github)](https://github.com/nwaizugbechukwuebuka/AI-Factory-Operations-Agent)

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-0077b5.svg?style=flat\&logo=linkedin)](https://www.linkedin.com/in/chukwuebuka-tobiloba-nwaizugbe/)

**Author:** Tobiloba Nwaizugbe


