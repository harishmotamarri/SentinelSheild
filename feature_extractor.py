
import re
import requests
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import tldextract
import numpy as np
import pandas as pd
import socket

class FeatureExtractor:

    def __init__(self, url):
        print(f"Initializing FeatureExtractor for {url}")
        self.url = url
        self.parsed_url = urlparse(url)
        print("Running tldextract...")
        # Disable fetching remote suffix list to prevent hanging
        # It will use the bundled snapshot if no cache exists
        extract = tldextract.TLDExtract(suffix_list_urls=())
        self.domain_info = extract(url)
        print("tldextract done.")
        self.domain = f"{self.domain_info.domain}.{self.domain_info.suffix}"
        
        # Default web content properties (updated if live check succeeds)
        self.web_content = None
        self.status_code = 0
        self.is_live = 0
        
        self.features = {}
        
    def fetch_web_content(self):
        print("Fetching web content...")
        try:
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
            response = requests.get(self.url, headers=headers, timeout=3)
            self.status_code = response.status_code
            if response.status_code == 200:
                self.is_live = 1
                self.web_content = BeautifulSoup(response.content, 'html.parser')
                print("Web content fetched successfully.")
        except Exception as e:
            print(f"Fetch failed: {e}")
            self.is_live = 0
            
    def extract_features(self):
        print("Starting feature extraction...")
        # 1. Structural Features
        self.features['url_len'] = len(self.url)
        
        # Char counts
        chars = ['@', '?', '-', '=', '.', '#', '%', '+', '$', '!', '*', ',', '//']
        for char in chars:
            self.features[char] = self.url.count(char)
            
        self.features['digits'] = sum(c.isdigit() for c in self.url)
        self.features['letters'] = sum(c.isalpha() for c in self.url)
        
        # 2. URL Patterns
        self.features['abnormal_url'] = 1 if re.search(r'http://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', self.url) else 0
        self.features['https'] = 1 if self.parsed_url.scheme == 'https' else 0
        
        shorteners = ['bit.ly', 'goo.gl', 'shorte.st', 'go2l.ink', 'x.co', 'ow.ly', 't.co', 'tinyurl', 'tr.im', 'is.gd', 'cli.gs', 'yfrog.com', 'migre.me', 'ff.im', 'tiny.cc', 'url4.eu', 'twit.ac', 'su.pr', 'twurl.nl', 'snipurl.com', 'short.to', 'BudURL.com', 'ping.fm', 'post.ly', 'Just.as', 'bkite.com', 'snipr.com', 'fic.kr', 'loopt.us', 'doiop.com', 'short.ie', 'kl.am', 'wp.me', 'rubyurl.com', 'om.ly', 'to.ly', 'bit.do', 't.cn', 'lnkd.in', 'db.tt', 'qr.ae', 'adf.ly', 'goo.gl', 'bitly.com', 'cur.lv', 'tinyurl.com', 'ow.ly', 'bit.ly', 'ity.im', 'q.gs', 'is.gd', 'po.st', 'bc.vc', 'twitthis.com', 'u.to', 'j.mp', 'buzurl.com', 'cutt.us', 'u.bb', 'yourls.org', 'x.co', 'prettylinkpro.com', 'scrnch.me', 'filoops.info', 'vzturl.com', 'qr.net', '1url.com', 'tweez.me', 'v.gd', 'tr.im', 'link.zip.net']
        self.features['Shortining_Service'] = 1 if any(s in self.url for s in shorteners) else 0
        
        self.features['having_ip_address'] = 1 if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', self.parsed_url.netloc) else 0
        
        # 3. Web Content Features (Need to fetch)
        # For performance, maybe skip fetch if just verifying structure first? No, model needs it.
        # self.fetch_web_content() # Moved to app.py call or explicit call
        
        self.features['web_http_status'] = self.status_code
        self.features['web_is_live'] = self.is_live
        
        # Heuristics for web content features (simplified)
        self.features['web_ext_ratio'] = 0 # Placeholder: External link ratio
        self.features['web_unique_domains'] = 0 # Placeholder
        self.features['web_favicon'] = 0
        self.features['web_csp'] = 0
        self.features['web_xframe'] = 0
        self.features['web_hsts'] = 0
        self.features['web_xcontent'] = 0
        self.features['web_security_score'] = 0 # Placeholder
        
        if self.web_content:
            # Basic content analysis if fetched
            forms = self.web_content.find_all('form')
            self.features['web_forms_count'] = len(forms)
            
            inputs = self.web_content.find_all('input')
            self.features['web_password_fields'] = sum(1 for i in inputs if i.get('type') == 'password')
            self.features['web_hidden_inputs'] = sum(1 for i in inputs if i.get('type') == 'hidden')
            self.features['web_has_login'] = 1 if self.features['web_password_fields'] > 0 else 0
            
            # Simple heuristic for SSL validity
            self.features['web_ssl_valid'] = 1 if self.parsed_url.scheme == 'https' else 0 
        else:
            self.features['web_forms_count'] = 0
            self.features['web_password_fields'] = 0
            self.features['web_hidden_inputs'] = 0
            self.features['web_has_login'] = 0
            self.features['web_ssl_valid'] = 0

        # 4. Phishing Specific Features
        urgency_words = ['urgent', 'verify', 'account', 'suspended', 'limit', 'secure', 'login', 'confirm', 'update', 'banking']
        self.features['phish_urgency_words'] = sum(1 for w in urgency_words if w in self.url.lower())
        
        security_words = ['secure', 'safe', 'protect', 'ssl', 'valid']
        self.features['phish_security_words'] = sum(1 for w in security_words if w in self.url.lower())
        
        brand_mentions = ['paypal', 'apple', 'google', 'microsoft', 'facebook', 'netflix', 'amazon']
        self.features['phish_brand_mentions'] = sum(1 for b in brand_mentions if b in self.url.lower())
        
        # Placeholder for complex heuristics
        self.features['phish_brand_hijack'] = 0 
        self.features['phish_multiple_subdomains'] = 1 if self.url.count('.') > 3 else 0
        self.features['phish_long_path'] = 1 if len(self.parsed_url.path) > 50 else 0
        self.features['phish_many_params'] = 1 if len(self.parsed_url.query.split('&')) > 3 else 0
        
        suspicious_tlds = ['zip', 'review', 'country', 'kim', 'cricket', 'science', 'work', 'party', 'gq', 'link']
        self.features['phish_suspicious_tld'] = 1 if self.domain_info.suffix in suspicious_tlds else 0
        
        # 'Adv' features - likely from advanced analysis library, guessing implementation
        self.features['phish_adv_exact_brand_match'] = 0
        self.features['phish_adv_brand_in_subdomain'] = 0
        self.features['phish_adv_brand_in_path'] = 0
        self.features['phish_adv_hyphen_count'] = self.url.count('-')
        self.features['phish_adv_number_count'] = sum(c.isdigit() for c in self.url) # Duplicate of 'digits'?
        self.features['phish_adv_suspicious_tld'] = self.features['phish_suspicious_tld']
        self.features['phish_adv_long_domain'] = 1 if len(self.domain) > 20 else 0
        self.features['phish_adv_many_subdomains'] = self.features['phish_multiple_subdomains']
        self.features['phish_adv_encoded_chars'] = 1 if '%' in self.url else 0
        self.features['phish_adv_path_keywords'] = 0 # Placeholder
        self.features['phish_adv_has_redirect'] = 1 if '//' in self.parsed_url.path else 0 # Simple redirect check
        self.features['phish_adv_many_params'] = self.features['phish_many_params']
        
        hacked_terms = ['hacked', 'pwned', 'steal', 'crack']
        self.features['path_has_hacked_terms'] = sum(1 for w in hacked_terms if w in self.parsed_url.path.lower())
        
        suspicious_exts = ['.exe', '.jar', '.js', '.vbs', '.bat', '.cmd', '.msi', '.pif', '.scr']
        self.features['suspicious_extension'] = 1 if any(self.url.endswith(ext) for ext in suspicious_exts) else 0
        
        self.features['path_underscore_count'] = self.parsed_url.path.count('_')
        self.features['is_gov_edu'] = 1 if self.domain_info.suffix in ['gov', 'edu'] or self.domain_info.suffix.endswith('.gov') or self.domain_info.suffix.endswith('.edu') else 0
        
        # Return dataframe with columns sorted as in the model
        ordered_features = [
             'url_len', '@', '?', '-', '=', '.', '#', '%', '+', '$', '!', '*', ',', '//', 
             'digits', 'letters', 'abnormal_url', 'https', 'Shortining_Service', 
             'having_ip_address', 'web_http_status', 'web_is_live', 'web_ext_ratio', 
             'web_unique_domains', 'web_favicon', 'web_csp', 'web_xframe', 'web_hsts', 
             'web_xcontent', 'web_security_score', 'web_forms_count', 'web_password_fields', 
             'web_hidden_inputs', 'web_has_login', 'web_ssl_valid', 'phish_urgency_words', 
             'phish_security_words', 'phish_brand_mentions', 'phish_brand_hijack', 
             'phish_multiple_subdomains', 'phish_long_path', 'phish_many_params', 
             'phish_suspicious_tld', 'phish_adv_exact_brand_match', 
             'phish_adv_brand_in_subdomain', 'phish_adv_brand_in_path', 
             'phish_adv_hyphen_count', 'phish_adv_number_count', 
             'phish_adv_suspicious_tld', 'phish_adv_long_domain', 
             'phish_adv_many_subdomains', 'phish_adv_encoded_chars', 
             'phish_adv_path_keywords', 'phish_adv_has_redirect', 
             'phish_adv_many_params', 'path_has_hacked_terms', 'suspicious_extension', 
             'path_underscore_count', 'is_gov_edu'
        ]
        
        # Ensure ordering
        return pd.DataFrame([self.features], columns=ordered_features).fillna(0)

# Test run if executed directly
if __name__ == "__main__":
    extractor = FeatureExtractor("http://google.com")
    extractor.fetch_web_content()
    df = extractor.extract_features()
    print(df.T)
