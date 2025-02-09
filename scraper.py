import re
from urllib.parse import urlparse
from urllib.parse import parse_qs
import time
from collections import defaultdict
from bs4 import BeautifulSoup



DELAY = float(config["CRAWLER"]["POLITENESS"])
all_last_times = defaultdict(int)
visited = set()
trap_check = defaultdict(int)


def is_low_information(resp):
    #does more links than words also count as low info???? - - - - - - - - - - 
    try:
        soup = BeautifulSoup(resp.raw_response.content, "html.parser")
        text = soup.get_text(separator=" ").strip()
        words = text.split()
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
    # if greater than 10 MB, too large for us to crawl - - - - - - - - - - - - - 
    return True




def scraper(url, resp):

    parsed = urlparse(url)

    # Sleep until the politness delay is met
    authority = parsed.netloc
    global all_last_times
    current_time = time.time()

    last_time = all_last_times[authority]
    if current_time - last_time < DELAY:
        time.sleep(DELAY - (current_time - last_time))
    all_last_times[authority] = time.time()



    # Defragment and clean to get the base URL
    cleaned_base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}".rstrip("/").lower()

    
    # How to handle redirection ????? - - - - - - - - - - - - - - - - - -


    # Avoid bad links or previously visited links. 
    if cleaned_base in visited or is_low_information(resp) or is_trap(resp, parsed, cleaned_base) or is_duplicate(resp) or is_large(resp):
        return []


    # Track as visited
    visited.add(cleaned_base)

    

    # # Extract valid URLs
    # links = [urljoin(url, a["href"]).split("#")[0] for a in soup.find_all("a", href=True)]
    # return [link for link in links if is_valid(link)]


    # ------------------------------------------------------------------------------------------------------------------------
    # This was the original two lines given in this function 
    # links = extract_next_links(url, resp)
    # return [link for link in links if is_valid(link)]



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
