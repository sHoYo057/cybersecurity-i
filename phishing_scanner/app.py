from flask import Flask, render_template, request
from urllib.parse import urlparse
import ipaddress

app = Flask(__name__)

def is_ip_address(domain):
    try:
        ipaddress.ip_address(domain)
        return True
    except:
        return False

def extract_features(url):
    parsed = urlparse(url)
    domain = parsed.netloc
    features = {
        'url_length': len(url),
        'has_ip': is_ip_address(domain),
        'has_at': '@' in url,
        'has_hyphen': '-' in domain,
        'subdomain_count': domain.count('.') - 1,
        'https': parsed.scheme == 'https',
    }
    return features

def phishing_score(features):
    score = 0
    score += features['url_length'] > 75
    score += features['has_ip']
    score += features['has_at']
    score += features['has_hyphen']
    score += features['subdomain_count'] > 2
    score += not features['https']
    return score

def is_phishing(url):
    features = extract_features(url)
    score = phishing_score(features)
    result = {
        "features": features,
        "score": score,
        "is_phishing": score >= 3
    }
    return result

@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    if request.method == 'POST':
        url = request.form['url']
        result = is_phishing(url)
        result['url'] = url
    return render_template('index.html', result=result)

if __name__ == '__main__':
    app.run(debug=True)
