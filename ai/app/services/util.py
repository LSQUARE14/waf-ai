from flask import request

def dumps_request():
    return {
        "method": request.method,
        "url": request.url,
        "headers": dict(request.headers),
        "body": request.get_data(as_text=True)
    }

RULE = r'''SecRuleEngine On\nSecRequestBodyAccess On\n\nSecRule ARGS|REQUEST_BODY "@rx (?i)\b((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\s*;\s*cat\s+\*" \
    "id:110001,phase:2,deny,status:403,log,severity:CRITICAL,msg:'Blocked command injection using IPv4 and cat wildcard'"'''

def opt(rule):
    return RULE

def opt1(rule):
    return 'SecRuleEngine On\nSecRequestBodyAccess On\n\n' + RULE