import re
import requests
from urllib.parse import urlparse, urljoin
from urllib.parse import parse_qs
import time
from collections import defaultdict
from bs4 import BeautifulSoup
from collections import Counter



DELAY = float(config["CRAWLER"]["POLITENESS"])
all_last_times = defaultdict(int)
visited = set()
trap_check = defaultdict(int)
REDIRECT_LIMIT = 6
unique_urls = set()
page_word_counts = dict()
longest_page = [None, 0]
word_freqs = Counter() 
subdomains = defaultdict(set)


def is_low_information(resp):
    #does more links than words also count as low info???? - - - - - - - - - - 
    try:
        soup = BeautifulSoup(resp.raw_response.content, "html.parser")
        text = soup.get_text(separator=" ").strip()
        words = text.split()
        low_info = ["login", "signup", "thank-you", "terms-of-service", "privacy-policy"]
        if any(word in resp.url.lower() for word in low_info):
            return True
        return len(words) < 100
    except Exception:
        return True

def is_trap(resp, parsed, cleaned_base):
    # How do we indentify traps?????? - - - - - - - - - - - - - 
    # its a very complicated process cuz there is no right or wrong answer - - - - - - - - - - - - - 
    return True

def is_duplicate(resp):
    # Do only how much the assignment asks for. It doesnt use the word "duplicate" but uses "similarity" in the instructions - - - - - - - - - - - - - 
    return True

def is_large(resp):
    # if greater than 10 MB, too large for us to crawl (converted to mb)- - - - - - - - - - - - - 
    try:
        file_size = int(resp.headers.get('content-length'))
        file_size = file_size / (1024 * 1024)
        print(file_size)
    except Exception:
        return False
    if file_size > 10:
        return True

def get_stop_words(file):
    stop_words = set()
    with open(filename, "r", encoding="utf-8") as file:
        for line in file:
            stop_words.add(line.strip())
    return stop_words




def scraper(url, resp):

    if not is_valid(url):
        return []

    parsed = urlparse(url)

    # Sleep until the politness delay is met
    full_domain = parsed.netloc
    global all_last_times
    current_time = time.time()

    last_time = all_last_times[full_domain]
    if current_time - last_time < DELAY:
        time.sleep(DELAY - (current_time - last_time))
    all_last_times[full_domain] = time.time()



    # Defragment and clean to get the base URL
    cleaned_base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}".rstrip("/").lower()

    
    # How to handle redirection ????? - - - - - - - - - - - - - - - - - -
    redir_num = 0
    while resp.is_redirect:
        if redir_num >= REDIRECT_LIMIT:
            return []

        redirect_url = resp.headers.get('Location')
        if not redirect_url:
            break
        
        # Making sure url is absolute
        redirect_url = urljoin(url, redirect_url)

        try:
            resp = requests.get(redirect_url, allow_redirects=False)  
            parse_url = redirect_url
            parsed = urlparse(parse_url)  
            redir_num += 1
        except requests.RequestException as exception:
            print(f"Url {redirect_url} has the exception: {exception}")
            return []
        
    parsing = BeautifulSoup(resp.text, 'html.parser')
    text = parsing.get_text()  
    print(f"The url {redirect_url} is indexing the text {text[:200]}")


    # Avoid bad links or previously visited links. 
    if cleaned_base in visited or is_low_information(resp) or is_trap(resp, parsed, cleaned_base) or is_duplicate(resp) or is_large(resp):
        return []


    # Track as visited
    visited.add(cleaned_base)

    # Add the defragmented URL to the unique set. Only inserts if unique.
    cleaned_defragmented = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    if parsed.query: 
        cleaned_defragmented += f"?{parsed.query}"
    cleaned_defragmented = cleaned_defragmented.rstrip("/").lower()
    unique_urls.add(cleaned_defragmented)

    # Get subdomain
    if "ics.uci.edu" in full_domain:
        subdomains[full_domain].add(cleaned_defragmented)

    # Get all words in the page
    soup = BeautifulSoup(resp.raw_response.content, "html.parser")
    text = soup.get_text(separator=" ")
    words = re.findall(r'\b[a-zA-Z]{1,}\b', text.lower())

    # Update longest page
    N = 0
    if words:
        N = len(words)
    if N > longest_page[1]:
        longest_page[0] = url
        longest_page[1] = N

    # 50 most common words from all pages. 
    stop_words = get_stop_words("stop_words_list.txt")
    for word in words:
        if word not in stop_words:
            word_frequencies[word] += 1





def extract_next_links(url, resp):
    # Implementation required.
    # url: the URL that was used to get the page
    # resp.url: the actual url of the page
    # resp.status: the status code returned by the server. 200 is OK, you got the page. Other numbers mean that there was some kind of problem.
    # resp.error: when status is not 200, you can check the error here, if needed.
    # resp.raw_response: this is where the page actually is. More specifically, the raw_response has two parts:
    #         resp.raw_response.url: the url, again
    #         resp.raw_response.content: the content of the page!
    # Return a list with the hyperlinks (as strings) scrapped from resp.raw_response.content
    return list()



def is_valid(url):
    # Decide whether to crawl this url or not. 
    # If you decide to crawl it, return True; otherwise return False.
    # There are already some conditions that return False.
    try:
        parsed = urlparse(url)
        if parsed.scheme not in set(["http", "https"]):
            return False
        return not re.match(
            r".*\.(css|js|bmp|gif|jpe?g|ico"
            + r"|png|tiff?|mid|mp2|mp3|mp4"
            + r"|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf"
            + r"|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names"
            + r"|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso"
            + r"|epub|dll|cnf|tgz|sha1"
            + r"|thmx|mso|arff|rtf|jar|csv"
            + r"|rm|smil|wmv|swf|wma|zip|rar|gz)$", parsed.path.lower())

    except TypeError:
        print ("TypeError for ", parsed)
        raise
