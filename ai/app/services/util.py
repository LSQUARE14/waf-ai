from flask import request

def dumps_request():
    return {
        "method": request.method,
        "url": request.url,
        "headers": dict(request.headers),
        "body": request.get_data(as_text=True)
    }