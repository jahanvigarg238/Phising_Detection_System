import re
import socket
import urllib.parse


def extract_features(url: str) -> dict:
    """Extract features from a URL. Refactored to reduce cognitive complexity."""
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        return {f: -1 for f in FEATURE_NAMES}

    hostname = parsed.hostname or ''
    path = parsed.path or ''
    query = parsed.query or ''
    scheme = parsed.scheme or ''
    full_url = url.lower()

    ip_pattern = re.compile(r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.){3}([01]?\d\d?|2[0-4]\d|25[0-5])')

    def ip_feature():
        return -1 if ip_pattern.search(hostname) else 1

    def url_length_feature():
        l = len(url)
        if l < 54:
            return 1
        if l <= 75:
            return 0
        return -1

    def shortener_feature():
        shorteners = ('bit.ly','tinyurl','goo.gl','t.co','ow.ly','is.gd',
                      'buff.ly','adf.ly','short.link','rebrand.ly')
        return -1 if any(s in full_url for s in shorteners) else 1

    def at_symbol():
        return -1 if '@' in url else 1

    def double_slash():
        return -1 if url.rfind('//') > 6 else 1

    def prefix_suffix():
        return -1 if '-' in hostname else 1

    def subdomain():
        dots = hostname.count('.')
        if dots == 1:
            return 1
        if dots == 2:
            return 0
        return -1

    def ssl_state():
        return 1 if scheme == 'https' else -1

    suspicious_tlds = ('.tk','.ml','.ga','.cf','.gq','.xyz','.top',
                       '.click','.loan','.win','.bid','.stream')
    tld = '.' + hostname.split('.')[-1] if '.' in hostname else ''

    def suspicious_tld_feature():
        return -1 if tld in suspicious_tlds else 1

    def favicon():
        return -1 if ip_pattern.search(hostname) else 1

    def port_feature():
        port = parsed.port
        return -1 if port not in (80, 443, 21, 22, 25, 110, None) else 1

    def https_token():
        return -1 if 'https' in hostname else 1

    def request_url():
        return 1 if path.count('/') <= 3 else -1

    def url_of_anchor():
        return -1 if len(query) > 50 else 1

    def static_zero():
        return 0

    def sfh():
        return -1 if 'blank' in full_url else 1

    def submitting_email():
        return -1 if 'mailto:' in full_url else 1

    def abnormal_url():
        return 1 if hostname in url else -1

    def redirect_feature():
        rc = full_url.count('redirect') + full_url.count('redir') + full_url.count('goto')
        return 1 if rc > 1 else 0

    def static_one():
        return 1

    def age_of_domain():
        return -1 if tld in suspicious_tlds else 1

    def dns_record():
        try:
            socket.gethostbyname(hostname)
            return 1
        except Exception:
            return -1

    def web_traffic():
        known_domains = ('google','facebook','youtube','amazon','twitter','instagram',
                         'linkedin','microsoft','apple','netflix','github','wikipedia',
                         'reddit','paypal','ebay','yahoo','bing','dropbox','spotify')
        return 1 if any(k in hostname for k in known_domains) else -1

    def page_rank(dns, web):
        return 1 if (scheme == 'https' and web == 1) else -1

    def google_index(dns):
        return 1 if dns == 1 else -1

    def statistical_report():
        phish_keywords = ('login','signin','verify','secure','account','update',
                          'confirm','banking','payment','password','credential',
                          'suspended','alert','unlock','validate','recover')
        phish_count = sum(1 for k in phish_keywords if k in full_url)
        return -1 if phish_count >= 2 else 1

    features = {
        'having_IP_Address': ip_feature(),
        'URL_Length': url_length_feature(),
        'Shortining_Service': shortener_feature(),
        'having_At_Symbol': at_symbol(),
        'double_slash_redirecting': double_slash(),
        'Prefix_Suffix': prefix_suffix(),
        'having_Sub_Domain': subdomain(),
        'SSLfinal_State': ssl_state(),
        'Domain_registeration_length': suspicious_tld_feature(),
        'Favicon': favicon(),
        'port': port_feature(),
        'HTTPS_token': https_token(),
        'Request_URL': request_url(),
        'URL_of_Anchor': url_of_anchor(),
        'Links_in_tags': static_zero(),
        'SFH': sfh(),
        'Submitting_to_email': submitting_email(),
        'Abnormal_URL': abnormal_url(),
        'Redirect': redirect_feature(),
        'on_mouseover': static_one(),
        'RightClick': static_one(),
        'popUpWidnow': static_one(),
        'Iframe': static_one(),
        'age_of_domain': age_of_domain(),
    }

    features['DNSRecord'] = dns_record()
    features['web_traffic'] = web_traffic()
    features['Page_Rank'] = page_rank(features['DNSRecord'], features['web_traffic'])
    features['Google_Index'] = google_index(features['DNSRecord'])
    features['Links_pointing_to_page'] = static_zero()
    features['Statistical_report'] = statistical_report()

    return features


FEATURE_NAMES = [
    'having_IP_Address','URL_Length','Shortining_Service','having_At_Symbol',
    'double_slash_redirecting','Prefix_Suffix','having_Sub_Domain','SSLfinal_State',
    'Domain_registeration_length','Favicon','port','HTTPS_token','Request_URL',
    'URL_of_Anchor','Links_in_tags','SFH','Submitting_to_email','Abnormal_URL',
    'Redirect','on_mouseover','RightClick','popUpWidnow','Iframe','age_of_domain',
    'DNSRecord','web_traffic','Page_Rank','Google_Index','Links_pointing_to_page',
    'Statistical_report'
]


def features_to_dataframe(features: dict):
    import pandas as pd
    return pd.DataFrame([features])[FEATURE_NAMES]