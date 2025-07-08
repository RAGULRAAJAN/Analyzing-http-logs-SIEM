# Splunk HTTP Log Analysis

## Introduction

This workshop will guide you through practical HTTP log analysis using Splunk. By the end of this session, you'll have essential skills for detecting suspicious web activity, identifying server errors, and analyzing web traffic patterns through real-world examples.

## Prerequisites

* Access to a Splunk instance
* Basic knowledge of Splunk's search processing language (SPL)
* Downloadable sample dataset (Zeek-style HTTP logs in JSON format)

## Workshop Overview

In this hands-on session, you will:

1. Import HTTP log data into Splunk
2. Execute targeted queries to analyze web traffic patterns
3. Identify potential security issues and anomalies
4. Detect large file transfers that could indicate data exfiltration
5. Create documentation of your findings

## Dataset Preparation

**Sample Dataset**: Zeek-style HTTP logs in JSON format

**Download Link**: [HTTP Log Sample File](http.log)

## Data Ingestion Process

1. **Access Splunk**: Open your Splunk web interface
2. **Navigate to Data Input**: Go to Settings → Add Data
3. **Select Input Method**: Choose "Upload" option
4. **Select File**: Browse to your downloaded `synthetic_zeek_http.json` file
5. **Configure Source Type**:
   * Select "json" from predefined types, or
   * Create a custom source type named "zeek:http"
6. **Select Index**:
   * Use "main" for general purpose, or
   * Create a dedicated index named "http_lab" (recommended for isolation)
7. **Complete Upload**: Review settings and submit
8. **Verify Data**: Run a basic search to confirm ingestion

## Analysis Exercises

### Exercise 1: Top Traffic Sources

**Objective**: Identify the top 10 client IP addresses generating web traffic

**Query**:
```
index=http_lab sourcetype="json"
| stats count by "id.orig_h"
| sort -count
| head 10
```

**Analysis Questions**:
* Which IP addresses generate the most traffic?
* Is the distribution expected or are there outliers?
* Could any of these high-volume sources indicate automated tools or scanning?

### Exercise 2: Server Error Analysis

**Objective**: Quantify and analyze HTTP 5xx server errors

**Query**:
```
index=http_lab sourcetype="json" status_code>=500 status_code<600
| stats count as server_errors
```

**Extended Analysis**:
```
index=http_lab sourcetype="json" status_code>=500 status_code<600
| stats count by status_code, "id.resp_h"
| sort -count
```

**Analysis Questions**:
* How many server errors occurred during the captured timeframe?
* Which servers experienced the most errors?
* Do the errors follow any temporal pattern?

### Exercise 3: Suspicious User-Agent Detection

**Objective**: Identify potentially malicious automated tools by examining User-Agent strings

**Query**:
```
index=http_lab sourcetype="json" user_agent IN ("sqlmap/1.5.1", "curl/7.68.0", "python-requests/2.25.1", "botnet-checker/1.0")
| stats count by user_agent
```

**Extended Analysis**:
```
index=http_lab sourcetype="json"
| regex user_agent="(?i)(sqlmap|curl|python|bot|scanner)"
| stats count by user_agent, "id.orig_h"
```

**Analysis Questions**:
* Which suspicious tools are being used to access your web resources?
* Are specific IPs associated with these suspicious User-Agents?
* What resources are being targeted by these tools?

### Exercise 4: Large File Transfer Detection

**Objective**: Identify potentially suspicious large file transfers

**Query**:
```
index=http_lab sourcetype="json" resp_body_len>500000
| table ts "id.orig_h" "id.resp_h" uri resp_body_len
| sort -resp_body_len
```

**Extended Analysis**:
```
index=http_lab sourcetype="json" resp_body_len>500000
| eval size_mb=round(resp_body_len/1024/1024, 2)
| table ts "id.orig_h" "id.resp_h" uri size_mb
| sort -size_mb
```

**Analysis Questions**:
* What are the largest files being transferred?
* Are these transfers expected based on business operations?
* Could any of these transfers represent data exfiltration?

### Exercise 5: Comprehensive Security Analysis (Bonus)

**Objective**: Create a combined query that highlights potentially suspicious activities

**Query**:
```
index=http_lab sourcetype="json" 
| eval is_suspicious=case(
    status_code>=400, "Error",
    resp_body_len>500000, "Large Transfer",
    match(user_agent, "(?i)(sqlmap|curl|python|bot|scanner)"), "Suspicious Tool",
    1==1, "Normal")
| stats count by is_suspicious
| sort -count
```

## Documentation Requirements

For each exercise:
1. Take a screenshot showing your query and results
2. Write a brief analysis of what you observed (2-3 sentences)
3. Note any additional investigations you would perform based on findings

## Follow-up Activities

* Create a dashboard combining these queries for ongoing monitoring
* Set up alerts for critical patterns discovered during analysis
* Develop a baseline of normal HTTP activity to better identify anomalies

## Conclusion

By completing this workshop, you've developed practical skills in HTTP log analysis using Splunk. These techniques form the foundation of effective web security monitoring and can be extended to create comprehensive detection capabilities for your organization.
