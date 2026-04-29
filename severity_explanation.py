import phantom.rules as phantom
import json
#from datetime import datetime

def on_start(container):
    
    severity_explanation(container = container)
    return

def severity_explanation(container = None, **kwargs):
    if not container:
        return {"status": "failed", "message": "no_container_data"}
    
    container_id = container.get("id", "N/A")
    severity = str(container.get("severity", "unknown")).lower()
    
    severity_explanations = {
        "high": """RED ALERT - CRITICAL SEVERITY THREAT

This threat poses a critical risk to the organization and requires immediate response.

THREAT INDICATORS:
• Active exploitation detected or confirmed
• Direct impact on critical business services
• High probability of data loss or unauthorized access
• Multiple systems potentially compromised
• Sensitive or proprietary data at risk
• Potential for significant financial losses
• Regulatory compliance violations possible

RESPONSE REQUIREMENTS:
1. Activate incident response team immediately
2. Isolate affected systems from network
3. Conduct deep forensic analysis
4. Document all actions and findings
5. Notify senior management and stakeholders
6. Prepare for potential data breach notification
7. Preserve evidence for legal proceedings

ESCALATION:
• Immediate notification to CISO
• Engage external incident response team if needed
• Consider law enforcement notification
• Prepare public communications if necessary

TIME TO RESPOND: Within 15 minutes
PRIORITY LEVEL: CRITICAL (P1)""",
    
    "medium": """ORANGE ALERT - MEDIUM SEVERITY THREAT

This threat requires rapid investigation and may affect a limited number of systems 
or users. Response should be initiated within business hours.

THREAT INDICATORS:
• Suspicious activity detected requiring investigation
• Partial impact on services or limited user base
• Potential for temporary service disruption
• Medium impact on system performance
• Unauthorized access attempts or modifications
• Anomalous network or system behavior
• Potential credential compromise

RESPONSE REQUIREMENTS:
1. Open formal investigation case in SOAR
2. Gather and analyze relevant logs and data
3. Verify affected accounts or systems
4. Implement initial containment measures
5. Interview affected users if necessary
6. Document all investigation steps
7. Prepare preliminary findings report

INVESTIGATION STEPS:
• Timeline reconstruction
• Log analysis and correlation
• System integrity verification
• User activity review
• Network traffic analysis

TIME TO RESPOND: Within 2-4 hours
PRIORITY LEVEL: HIGH (P2)""",
    
    "low": """GREEN ALERT - LOW SEVERITY THREAT

This threat does not pose an immediate risk and can be addressed during standard 
operations. Monitoring and documentation are recommended.

THREAT INDICATORS:
• Informational alerts from monitoring systems
• Minor anomalies with negligible impact
• Routine system activities outside normal parameters
• Non-critical system updates or patches
• Low-risk suspicious activity
• Potential false positives from detection systems

RESPONSE REQUIREMENTS:
1. Log alert in tracking system
2. Schedule for periodic review
3. Correlate with similar alerts
4. Analyze patterns over time
5. Update detection rules if needed
6. Document findings and actions
7. Archive for future reference

MONITORING ACTIONS:
• Continue normal monitoring
• Weekly review of similar alerts
• Monthly trend analysis
• Quarterly rule effectiveness review

TIME TO RESPOND: Within 24-48 hours
PRIORITY LEVEL: LOW (P3)"""
                   }
    # Get appropriate explanation based on severity level
    explanation = severity_explanations.get(
        severity, "No specific explanation available for this severity level. Please contact the security team for clarification.")
    # Store results in dictionary for use in subsequent playbook actions
    results = {
        "severity_level": severity,
        "explanation": explanation,
        "container_id": container_id,
        #"timestamp": str(datetime.now()),
        "status": "explanation_generated"
    }
    
    phantom.debug(f"Results generated: {results}")
    
    return results

def on_finish(container):
    
    return