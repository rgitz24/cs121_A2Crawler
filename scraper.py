import re
from urllib.parse import urlparse, urljoin
from urllib.parse import parse_qs
import time
from collections import defaultdict
from bs4 import BeautifulSoup
from collections import Counter
from simhash import Simhash
import configparser



config = configparser.ConfigParser()
config.read("config.ini")
try:
    DELAY = float(config["CRAWLER"]["POLITENESS"])
except KeyError as e:
    raise KeyError(f"Missing key in config.ini")

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
LOG_FILE = "log.txt"

def log_write(message):
    print(message)
    with open(LOG_FILE, "a", encoding="utf-8") as log_file:
        log_file.write(message + "\n")

def print_report():

    log_write(" ")
    log_write("----------------###### Crawler Report ######----------------\n")
    
    unique_pages_count = len(unique_urls)
    log_write(f"Number of unique pages found: {unique_pages_count}\n")

    log_write(f"Longest page url: {longest_page[0]}   Word count: {longest_page[1]}\n")

    top_50 = word_freqs.most_common(50)
    for word, freq in top_50:
        log_write(f"{word} {freq}")
    log_write("\n")

    sorted_subdomains = sorted(subdomains.keys())
    log_write(f"Subdomains count: {len(sorted_subdomains)}")
    for subdomain in sorted_subdomains:
        log_write(f"{subdomain}, {len(subdomains[subdomain])}")

    log_write("\n")
    log_write("----------------############################----------------")


    

def is_low_information(resp):
    try:
        if resp.raw_response and resp.raw_response.content:
            soup = BeautifulSoup(resp.raw_response.content, "html.parser")
            text = soup.get_text(separator=" ").strip()
            words = text.split()
            return len(words) < 100
        return True
    except Exception as e:
        log_write(f"Error with Beautful Soup when checking low information: {e}")
        return True


def is_duplicate(resp):
    try:
        parsing = BeautifulSoup(resp.raw_response.content, "html.parser")
        content = parsing.get_text(separator=" ").strip()
        simhash = Simhash(content)
        for url_prev, simhash_prev in list(simhash_storage.items()):
            if simhash.distance(simhash_prev) < 5: 
                log_write(f"Similarity between resp.url: {resp.url} and prev_url: {url_prev}")
                return True

        simhash_storage[resp.url] = simhash
        return False

    except Exception as exception:
        log_write(f"Error in is_duplicate. Exception: {exception}")
        return False


def is_large(resp):
    try:
        file_size = None
        if resp.raw_response:
            if resp.raw_response.content:
                file_size = len(resp.raw_response.content)
                file_size = int(file_size) / (1024 * 1024)
                log_write(f"File size of {resp.url}: {file_size:.2f} MB")
                if file_size > 10:
                    return True
        if file_size is None:
            return True
        return False
    except Exception as e:
        log_write(f"Error in is_large: {e}")
        return True
    

def get_stop_words(file):
    stop_words = set()
    try:
        with open(file, "r", encoding="utf-8") as file:
            for line in file:
                stop_words.add(line.strip())
        return stop_words
    except FileNotFoundError:
        log_write(f"Error: Stop words file not found")
    except Exception as e:
        log_write(f"Error reading stop words file: {e}")


def defragment_and_clean(parsed):
    cleaned_defragmented = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    if parsed.query: 
        cleaned_defragmented += f"?{parsed.query}"
    cleaned_defragmented = cleaned_defragmented.rstrip("/").lower()
    return cleaned_defragmented


def scraper(url, resp):
    
    parsed = urlparse(url)

    # Get defragmented URL
    cleaned_defragmented = defragment_and_clean(parsed)
    log_write(f"Cleaned_defragmented URL: {cleaned_defragmented}")

    if cleaned_defragmented in unique_urls or cleaned_defragmented in avoid_urls:
        log_write(f"Skipping already visited or avoided URL: {cleaned_defragmented}")
        return []
    
    # Handle redirection
    # Making sure url is absolute
    if resp.status in {301, 302, 303, 307, 308}:
        log_write(f"Handling redirection")
        location = resp.headers.get('Location')
        if location:
            redirect_url = urljoin(url, location)
            parsed_redirect = urlparse(redirect_url)
            redirect_url = defragment_and_clean(parsed_redirect)
            log_write(f"Redirect url cleaned_defragmented: {redirect_url}\n")
            
            if redir_dict.get(redirect_url, 0) >= REDIRECT_LIMIT:
                avoid_urls.add(redirect_url)
                return []
            if redirect_url in unique_urls:
                return []
        
            redir_dict[redirect_url] += 1
            redir_dict[url] += 1
            log_write(f"Redirecting from {url} to {redirect_url}")

            return [redirect_url]
        else:
            return []


    
    # Sleep until the politness delay is met
    full_domain = parsed.netloc
    global all_last_times
    current_time = time.time()

    last_time = all_last_times[full_domain]
    if current_time - last_time < DELAY:
        log_write(f"Sleep time: {DELAY - (current_time - last_time)}")
        time.sleep(DELAY - (current_time - last_time))
    all_last_times[full_domain] = time.time()

        
    # Avoid bad links or previously visited links.
    if resp.status in {403, 404, 500, 503} or is_low_information(resp) or is_large(resp) or is_duplicate(resp):
        avoid_urls.add(cleaned_defragmented)
        log_write(f"Bad link found in check in scraper")
        return []

    unique_urls.add(cleaned_defragmented)

    # Get ics.uci.edu subdomains
    if "ics.uci.edu" in full_domain:
        subdomains[full_domain].add(cleaned_defragmented)

    # Get all words in the page
    try:
        soup = BeautifulSoup(resp.raw_response.content, "html.parser")
        text = soup.get_text(separator=" ")
        words = re.findall(r'\b[a-zA-Z]{2,}\b', text.lower())
    except Exception as e:
        log_write(f"Error getting all words from the page: {e}")
        words = []

    # Update longest page
    N = 0
    if words:
        N = len(words)
    if N > longest_page[1]:
        longest_page[0] = url
        longest_page[1] = N
        log_write(f"New longest page: {url} ({len(words)} words)")

    # 50 most common words from all pages. 
    stop_words = get_stop_words("stop_words_list.txt")
    for word in words:
        if word not in stop_words:
            word_freqs[word] += 1


    # Extract valid urls from this page
    links = extract_next_links(url, resp)
    return links

    






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
        unique_links = set()

        for anchor in soup.find_all("a", href=True):
            relative_link = anchor["href"]
            absolute_link = urljoin(url, relative_link)
            absolute_link = absolute_link.split("#")[0]
            if is_valid(absolute_link): 
                unique_links.add(absolute_link)
        log_write(f"Extracted {len(unique_links)} unique valid links from {url}")
        return list(unique_links)

    except Exception as e:
        log_write(f"Error extracting links from {url}: {e}")
        return []




def is_valid(url):
    try:
        parsed = urlparse(url)

        if parsed.scheme not in set(["http", "https"]):
            return False
        
        if url in avoid_urls or url in unique_urls:
            return False

        parsed_netloc = parsed.netloc.lower()
        parsed_path = parsed.path.lower()
        parsed_query = parsed.query.lower()

        if "wiki.ics.uci.edu" in parsed_netloc or "sli.ics.uci.edu":
            return False

        # Don't crawl if not valid domain
        allowed_domains = {"ics.uci.edu", "cs.uci.edu", "informatics.uci.edu", "stat.uci.edu"}
        parts = parsed_netloc.split(".")
        if len(parts) < 3:
            return False
        domain = ".".join(parts[-3:])
        if domain not in allowed_domains:
            return False       


        # Don't crawl if these words are in the path
        trap_keys = {"calendar", "sessionid", "events", "wiki", "login", "brochure"}  
        if any(keyword in parsed_path for keyword in trap_keys):
            return False


        # Don't crawl if these words are in the query keys
        query_params = parse_qs(parsed_query, keep_blank_values=True)
        search_keywords = {"share", "search", "calendar", "sessionid", "events"}
        for key, values in query_params.items():
            if key in search_keywords or key.startswith("filter"):
                return False
            for val in values:
                if any(keyword in val for keyword in search_keywords):
                    return False  


        # Depth is too much
        if parsed.path.count("/") > 9:
            return False
        

        # Too many query params
        if len(query_params) > 9:
            return False
        

        # Calendar trap
        calendar_patterns = [
            r".*(\d{4})[-/](\d{1,2})[-/](\d{1,2}).*",  
            r".*(year=\d{4}|month=\d{1,2}|day=\d{1,2}).*", 
        ]
        for pattern in calendar_patterns:
            if re.search(pattern, parsed.query):
                return False


        # # Pagination trap
        # pagination_words = ["page", "p"]
        # for param in pagination_words:
        #     if param in query_params:
        #         try:
        #             num = int(query_params[param][0])
        #             if num > 20:
        #                 return False
        #         except ValueError:
        #             pass


        return not re.match(
            r".*\.(apk|css|js|bmp|gif|jpe?g|ico|img"
            + r"|png|tiff?|mid|mp2|mp3|mp4"
            + r"|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf"
            + r"|ps|eps|tex|pps|ppt|ppsx|pptx|doc|docx|xls|xlsx|names"
            + r"|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso"
            + r"|epub|dll|cnf|tgz|sha1"
            + r"|thmx|mso|arff|rtf|jar|csv"
            + r"|rm|smil|wmv|swf|wma|zip|rar|gz)$", parsed.path.lower())

    except TypeError:
        log_write(f"TypeError for {parsed}")
        raise
