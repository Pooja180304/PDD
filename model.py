import ipaddress
import re
from bs4 import BeautifulSoup
import requests
import whois
import urllib
import urllib.request
from datetime import datetime
import requests
import json
import csv
import time
import socket
import ssl


global BASE_SCORE
global PROPERTY_SCORE_WEIGHTAGE
BASE_SCORE = 50  
PROPERTY_SCORE_WEIGHTAGE = {
    'domain_rank': 0.9,
    'domain_age': 0.3,
    'is_url_shortened': 0.8,
    'hsts_support': 0.1,
    'ip_present': 0.8,
    'url_redirects': 0.2,
    'too_long_url': 0.1,
    'too_deep_url': 0.5,
    'content': 0.1
}




def validate_url(url):
    try:
        response = requests.get(url)
        return response.status_code

    except requests.exceptions.RequestException:
        return False

def include_protocol(url):
    try:
        if not url.startswith('http://') and not url.startswith('https://'):
            url = 'https://' + url
        return url

    except:
        return url


def get_domain_rank(domain):
    
    with open('static/data/sorted-top1million.txt') as f:
        top1million = f.read().splitlines()

    is_in_top1million = binary_search(top1million, domain)

    if is_in_top1million == 1:
        with open('static/data/domain-rank.json', 'r') as f:
            domain_rank_dict = json.load(f)
        rank = domain_rank_dict.get(domain, 0)
        return int(rank)
    else:
        return 0



def binary_search(arr, x):
    low = 0
    high = len(arr) - 1
    while low <= high:
        mid = (low + high) // 2
        if arr[mid] == x:
            return 1
        elif arr[mid] < x:
            low = mid + 1
        else:
            high = mid - 1
    return 0


def whois_data(domain):
    try:
        whois_data = whois.whois(domain)
        creation_date = whois_data.creation_date
        data = {}

        if type(creation_date) is list:
            creation_date = creation_date[0]
            whois_data['creation_date'] = [d.strftime('%Y-%m-%d %H:%M:%S') for d in whois_data.creation_date]

        if type(whois_data.updated_date) is list:
            whois_data['updated_date'] = [d.strftime('%Y-%m-%d %H:%M:%S') for d in whois_data.updated_date]
        

        if type(whois_data.expiration_date) is list:
            whois_data['expiration_date'] = [d.strftime('%Y-%m-%d %H:%M:%S') for d in whois_data.expiration_date]
        


        if creation_date == None:
            age = 'Not Given'
        else:
            age = (datetime.now() - creation_date).days / 365 

        for prop in whois_data:
            if type(whois_data[prop]) is list:
                data[pascal_case(prop)] = ', '.join(whois_data[prop])
            else:
                data[pascal_case(prop)] = whois_data[prop]

        return {'age':age, 'data':data}

    except Exception as e:
        print(f"Error: {e}")
        return False


def pascal_case(s):
    result = s.replace('_',' ').title()
    return result



def hsts_support(url): 
    try:
        response = requests.get(url)
        headers = response.headers
        if 'Strict-Transport-Security' in headers:
            return 1
        else:
            return 0
    except:
        return 0



def is_url_shortened(domain): 
    try:
        with open('static/data/url-shorteners.txt') as f:
            services_arr = f.read().splitlines()
        
        for service in services_arr:
            if service in domain:
                return 1
        return 0
    except:
        return 0



def ip_present(url):
    try:
        ipaddress.ip_address(url)
        result = 1
    except:
        result = 0
    return result



def url_redirects(url):
    try:
        response = requests.get(url)
        if len(response.history) > 1:
            
            url_history = [] 
            for resp in response.history:
                url_history.append(resp.url)
            return url_history
        else:
            return 0
    except Exception as e:
        
        return 0



def too_long_url(url):
    if len(url) > 75:
        return 1
    else:
        return 0



def too_deep_url(url):
    slashes = -2 
    for i in url:
        if i == '/':
            slashes += 1

    if slashes > 5:
        return 1
    else:
        return 0



 
def content_check(url):
    try:

        response = requests.get(url)
        soup = BeautifulSoup(response.content, 'html.parser')

        result = {'onmouseover':0, 'right-click':0, 'form':0, 'iframe':0, 'login':0, 'popup':0}

        
        if soup.find(onmouseover=True):
            result['onmouseover'] = 1


        
        if soup.find_all('body', {'oncontextmenu': 'return false;'}):
            result['right-click'] = 1


        
        if soup.find_all('form'):
            result['form'] = 1

        
        if soup.find_all('iframe'):
            result['iframe'] = 1

        
        if soup.find_all(text=re.compile('password|email|forgotten|login')):
            result['login'] = 1

        
        if soup.find_all('div', {'class': 'popup'}):
            result['popup'] = 1
        
        return result

    except Exception as e:
        
        return 0



def phishtank_search(url):

    try:
        endpoint = "https://checkurl.phishtank.com/checkurl/"
        response = requests.post(endpoint, data={"url": url, "format": "json"})
        data = json.loads(response.content)
        if data['results']['valid'] == True:
            return 1
        return 0

    except Exception as e:
        
        return 0


def get_ip(domain):

    try:
        ip = socket.gethostbyname(domain)
        return ip

    except Exception as e:
        print(f"Error: {e}")
        return 0



def get_certificate_details(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as sslsock:
                cert = sslsock.getpeercert()


                
                issuer = dict(x[0] for x in cert['issuer'])
                if 'organizationName' in issuer:
                    ca_info = issuer['organizationName']
                else:
                    ca_info = issuer['commonName']


                
                not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                days_to_expiry = (not_after - datetime.now()).days

                
                revoked = False
                for crl in cert.get('crlDistributionPoints', ()):
                    try:
                        crl_data = ssl.get_server_certificate((crl.split('//')[1]).split('/')[0])
                        crl_obj = ssl.load_crl_der(ssl.PEM_to_DER_cert(crl_data))
                        if crl_obj.get_revoked_certificate_by_serial_number(cert['serialNumber']):
                            revoked = True
                            break
                    except Exception:
                        pass

                
                cipher = sslsock.cipher()
                cipher_suite = cipher[0]

                
                version = sslsock.version()

                
                subject = dict(x[0] for x in cert['subject'])
                common_name = subject['commonName']
                sans = [x[1] for x in cert['subjectAltName'] if x[0] == 'DNS']

                return {
                    'Issued By': ca_info,
                    'Issued To': common_name,
                    'Valid From': not_before.strftime('%Y-%m-%d %H:%M:%S %Z'),
                    
                    'Valid Till': not_after.strftime('%Y-%m-%d %H:%M:%S %Z'),
                    'Days to Expiry': days_to_expiry,
                    'Version': version,
                    'Is Certificate Revoked': revoked,
                    'Cipher Suite': cipher_suite
                    
                }
    except Exception as e:
        print(f"Error: {e}")
        return 0



def test(domain):
    
    with open('sorted-top1million.txt') as f:
        top1million = f.read().splitlines()
        




def calculate_trust_score(current_score, case, value):

    score = current_score

    if case == 'domain_rank':
        if value == 0:  
            score = current_score 
        elif value < 100000:  
            score = current_score + (PROPERTY_SCORE_WEIGHTAGE['domain_rank'] * BASE_SCORE)
        elif value < 500000:  
            score = current_score + (PROPERTY_SCORE_WEIGHTAGE['domain_rank'] * BASE_SCORE * 0.8)
        else:  
            score = current_score + (PROPERTY_SCORE_WEIGHTAGE['domain_rank'] * BASE_SCORE * 0.6)
        return score

    elif case == 'domain_age':
        if value < 5:
            score = current_score - (PROPERTY_SCORE_WEIGHTAGE['domain_age'] * BASE_SCORE)
        elif value >= 5 and value < 10:
            score = current_score
        elif value >= 10:
            score = current_score + (PROPERTY_SCORE_WEIGHTAGE['domain_age'] * BASE_SCORE)
        return score

    elif case == 'is_url_shortened':
        if value == 1:
            score = current_score - (PROPERTY_SCORE_WEIGHTAGE['is_url_shortened'] * BASE_SCORE)
        return score

    elif case == 'hsts_support':
        if value == 1:
            score = current_score + (PROPERTY_SCORE_WEIGHTAGE['hsts_support'] * BASE_SCORE)
        else:
            score = current_score - (PROPERTY_SCORE_WEIGHTAGE['hsts_support'] * BASE_SCORE)
        return score

    elif case == 'ip_present':
        if value == 1:
            score = current_score - (PROPERTY_SCORE_WEIGHTAGE['ip_present'] * BASE_SCORE)
        return score

    elif case == 'url_redirects':
        if value:
            score = current_score - (PROPERTY_SCORE_WEIGHTAGE['url_redirects'] * BASE_SCORE)
        return score

    elif case == 'too_long_url':
        if value == 1:
            score = current_score - (PROPERTY_SCORE_WEIGHTAGE['too_long_url'] * BASE_SCORE)
        return score

    elif case == 'too_deep_url':
        if value == 1:
            score = current_score - (PROPERTY_SCORE_WEIGHTAGE['too_deep_url'] * BASE_SCORE)
        return score