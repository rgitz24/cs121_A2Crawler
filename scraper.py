import re
import requests
from urllib.parse import urlparse, urljoin
from urllib.parse import parse_qs
import time
from collections import defaultdict
from bs4 import BeautifulSoup
from collections import Counter
from simhash import Simhash



DELAY = float(config["CRAWLER"]["POLITENESS"])
all_last_times = defaultdict(int)
trap_check = defaultdict(int)
REDIRECT_LIMIT = 6
unique_urls = set() # This means we already visited the url. The urls are all defragmented, which means it counts urls with different fragments as the same.
page_word_counts = dict()
longest_page = [None, 0]
word_freqs = Counter() 
subdomains = defaultdict(set)
redir_dict = defaultdict(int)
simhash_storage = {}

avoid_urls = set()


def is_low_information(resp):
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

def is_trap(resp, parsed, cleaned_defragmented):
    # How do we indentify traps?????? - - - - - - - - - - - - - 
    # its a very complicated process cuz there is no right or wrong answer - - - - - - - - - - - - - 
    return True

def is_duplicate(resp):
    # Do only how much the assignment asks for. It doesnt use the word "duplicate" but uses "similarity" in the instructions - - - - - - - - - - - - - 
    try:
        parsing = BeautifulSoup(resp.raw_response.content, "html.parser")
        content = parsing.get_text(separator=" ").strip()
        simhash = Simhash(content)
        for url_prev, simhash_prev in simhash_storage.items():
            if simhash.distance(simhash_prev) < 5: 
                print(f"Similarity between resp.url: {resp.url} and prev_url: {url_prev}")
                return True

        simhash_storage[resp.url] = simhash
        return False

    except Exception as exception:
        print(f"Exception: {exception}")
        return False

def is_large(resp):
    # if greater than 10 MB, too large for us to crawl (converted to mb)- - - - - - - - - - - - - 
    try:
        file_size = resp.headers.get('content-length')
        if file_size is None:
            return True
        file_size = int(file_size) / (1024 * 1024)
        print(file_size)
        if file_size > 10:
            return True
    except Exception as e:
        return True
    


def get_stop_words(file):
    stop_words = set()
    with open(file, "r", encoding="utf-8") as file:
        for line in file:
            stop_words.add(line.strip())
    return stop_words

def defragment_and_clean(parsed):
    cleaned_defragmented = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    if parsed.query: 
        cleaned_defragmented += f"?{parsed.query}"
    cleaned_defragmented = cleaned_defragmented.rstrip("/").lower()
    return cleaned_defragmented


def scraper(url, resp):

    if not is_valid(url):
        return []
    
    parsed = urlparse(url)

    # Get defragmented URL
    cleaned_defragmented = defragment_and_clean(parsed)

    if cleaned_defragmented in unique_urls or cleaned_defragmented in avoid_urls:
        return []
    
    # Handle redirection
    # Making sure url is absolute
    if resp.is_redirect:
        location = resp.headers.get('Location')
        if location:
            redirect_url = urljoin(url, location)
            parsed_redirect = urlparse(redirect_url)
            redirect_url = defragment_and_clean(parsed_redirect)

            if redir_dict.get(redirect_url, 0) >= REDIRECT_LIMIT:
                avoid_urls.add(redirect_url)
                return []
            if redirect_url in unique_urls:
                return []
        
            redir_dict[redirect_url] += 1
            print(f"Redirecting from {url} to {redirect_url}")

            return [redirect_url]
        else:
            return []


    # Sleep until the politness delay is met
    full_domain = parsed.netloc
    global all_last_times
    current_time = time.time()

    last_time = all_last_times[full_domain]
    if current_time - last_time < DELAY:
        time.sleep(DELAY - (current_time - last_time))
    all_last_times[full_domain] = time.time()

        
    # Avoid bad links or previously visited links. 
    if is_large(resp) or is_low_information(resp) or is_trap(resp, parsed, cleaned_defragmented) or is_duplicate(resp) or resp.status in {403, 404, 500, 503}:
        avoid_urls.add(cleaned_defragmented)
        return []

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
            word_freqs[word] += 1


    # Extract valid urls from this page
    links = extract_next_links(url, resp)
    return [link for link in links if is_valid(link)]

    






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
    
    if resp.status != 200 or not resp.raw_response:
        return []

    try:
        soup = BeautifulSoup(resp.raw_response.content, "html.parser")
        unique_links = set()  # should we be checking for traps here too and avoid extracting bad links or is that for scraper to handle???- - - - - - - - - -

        for anchor in soup.find_all("a", href=True):
            relative_link = anchor["href"]
            absolute_link = urljoin(url, relative_link)
            absolute_link = absolute_link.split("#")[0]
            if is_valid(absolute_link) and absolute_link not in avoid_urls: 
                unique_links.add(absolute_link)

        return list(unique_links)

    except Exception as e:
        print(f"Error extracting links from {url}: {e}")
        return []




def is_valid(url):
    try:
        parsed = urlparse(url)
        if parsed.scheme not in set(["http", "https"]):
            return False
        
        if url in avoid_urls:
            return False

        parsed_netloc = parsed.netloc.lower()
        parsed_path = parsed.path.lower()
        parsed_query = parsed.query.lower()

        # Don't crawl if not valid domain
        allowed_domains = {"ics.uci.edu", "cs.uci.edu", "informatics.uci.edu", "stat.uci.edu"}
        parts = parsed_netloc.split(".")
        if len(parts) < 3:
            return False
        domain = ".".join(parts[-3:])
        if domain not in allowed_domains:
            return False
        

        # Don't crawl if these words are in the path or query
        trap_keys = {"calendar", "sessionid", "sort", "filter", "ref"}  
        if any(keyword in parsed_query or keyword in parsed_path for keyword in trap_keys):
            return False

        # Don't crawl if these words are in the query
        query_params = {key.lower(): value for key, value in parse_qs(parsed.query).items()}
        search_keywords = {"query", "search", "results"}
        if any(param in query_params for param in search_keywords):
            return False

        # Don't crawl if these query keys repeat too too much
        if "page" in query_params:
            try:
                page_num = int(query_params.get("page", ["1"])[0])
                if page_num > 50:  
                    return False
            except ValueError:
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
