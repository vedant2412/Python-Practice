WEB_LOGS = [{'timestamp': 1678886400, 'src_ip': '10.1.1.100', 'status': 200, 'url': '/api/data'},
    {'timestamp': 1678886405, 'src_ip': '192.0.2.77', 'status': 401, 'url': '/admin/login'},
    {'timestamp': 1678886410, 'src_ip': '10.1.1.101', 'status': 404, 'url': '/home.html'},
    {'timestamp': 1678886415, 'src_ip': '203.0.113.12', 'status': 500, 'url': '/legacy/config'},
    {'timestamp': 1678886420, 'src_ip': '10.1.1.102', 'status': 200, 'url': '/images/logo.png'}]

TI_FEED = {
    '192.0.2.77': {'actor': 'ShadowHound', 'priority': 'Critical'},
    '203.0.113.12': {'actor': 'Botnet-Alpha', 'priority': 'High'},
    '104.28.5.150': {'actor': 'Phishing-Kit', 'priority': 'Medium'}, }



def enrich_and_filter_logs(WEB_LOGS, TI_FEED):
    enriched_log = []
    malicious_alerts = []

    for log in WEB_LOGS:
        source_ip = log.get('src_ip')
        if source_ip in TI_FEED:
            enriched_log = log.copy()
            enriched_log.update(TI_FEED[source_ip])
            malicious_alerts.append(enriched_log)
    return malicious_alerts
    
alerts = enrich_and_filter_logs(WEB_LOGS, TI_FEED)

import json
print(json.dumps(alerts, indent=2))