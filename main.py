import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from urllib.robotparser import RobotFileParser
import time
import collections
import hashlib
import logging

# --- Configuration ---
# IMPORTANT: DEFINE YOUR CRAWLER'S USER AGENT CLEARLY
MY_USER_AGENT = 'MyEnhancedDemoCrawler/1.0 (+http://mycrawler.example.com/info)' # CHANGE THIS

# Start with seed URLs
INITIAL_URLS = ['https://quotes.toscrape.com/']
# Limit crawl scope (only crawl pages on the initial host(s))
ALLOWED_DOMAINS = {urlparse(url).netloc for url in INITIAL_URLS}
# Limit the number of pages to fetch
MAX_PAGES = 50
# Default politeness delay if no Crawl-delay is specified (in seconds)
DEFAULT_DELAY = 2
# Request timeout
REQUEST_TIMEOUT = 15

# --- Logging Setup ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Data Structures ---
urls_to_visit = collections.deque(INITIAL_URLS)
visited_urls = set() # Store normalized URLs that have been processed or added to queue
visited_content_hashes = set() # Store hashes of content already processed
robot_parsers = {} # Cache RobotFileParser objects per domain {netloc: RobotFileParser}
domain_last_accessed = {} # Store last access time per domain {netloc: timestamp}

# --- Helper Functions ---

def normalize_url(page_url, link_url):
    """Normalizes a URL found on a page and resolves relative paths."""
    try:
        # Resolve relative URLs (like /page.html) using the base page URL
        absolute_url = urljoin(page_url, link_url.strip())
        parsed = urlparse(absolute_url)

        # Keep only scheme, netloc, path; convert scheme/netloc to lowercase
        # Optionally remove fragments (#) and common tracking params if needed
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()
        path = parsed.path
        # Remove fragment
        if not path: path = '/' # Ensure path exists

        # Reconstruct, potentially removing www. if desired (not done here)
        normalized = f"{scheme}://{netloc}{path}"

        # Optionally handle query parameters here (e.g., remove common trackers)
        if parsed.query:
             normalized += "?" + parsed.query # Keep query for now

        # Ensure scheme is http or https
        if scheme not in ['http', 'https']:
            return None

        return normalized
    except Exception as e:
        logging.warning(f"Could not normalize URL '{link_url}' on page '{page_url}': {e}")
        return None

def get_robot_parser(url):
    """Gets or creates the RobotFileParser for the URL's domain."""
    parsed_url = urlparse(url)
    netloc = parsed_url.netloc
    if netloc not in robot_parsers:
        robots_url = f"{parsed_url.scheme}://{netloc}/robots.txt"
        parser = RobotFileParser()
        parser.set_url(robots_url)
        try:
            logging.info(f"Fetching robots.txt for {netloc} from {robots_url}")
            # Use our specific user agent to fetch robots.txt too
            headers = {'User-Agent': MY_USER_AGENT}
            response = requests.get(robots_url, headers=headers, timeout=REQUEST_TIMEOUT)
            response.raise_for_status() # Check for 4xx/5xx errors
            # Check content type - some sites return HTML for robots.txt errors
            if 'text/plain' in response.headers.get('Content-Type', ''):
                 parser.parse(response.text.splitlines())
            else:
                 logging.warning(f"Received non-plain text content-type for robots.txt at {robots_url}")
                 # Assume disallowed if robots.txt is weird? Or assume allowed? Depends on policy.
                 # For this example, we'll allow if parsing fails but log it.
                 parser.allow_all = True # Default if parsing fails/content wrong

        except requests.exceptions.HTTPError as e:
            # Treat 404 (Not Found) as allowed, other errors might mean temporary issues
            if e.response.status_code == 404:
                 logging.info(f"robots.txt not found for {netloc} (status 404), assuming allowed.")
                 parser.allow_all = True
            else:
                 logging.error(f"HTTPError fetching robots.txt for {netloc}: {e}. Assuming disallowed for safety.")
                 parser.disallow_all = True # Disallow if we can't be sure
        except requests.exceptions.RequestException as e:
            logging.error(f"Error fetching robots.txt for {netloc}: {e}. Assuming disallowed for safety.")
            parser.disallow_all = True # Disallow if network error
        except Exception as e:
            logging.error(f"Unexpected error reading robots.txt for {netloc}: {e}. Assuming disallowed.")
            parser.disallow_all = True

        robot_parsers[netloc] = parser
    return robot_parsers[netloc]

def can_fetch_url(parser, url):
    """Checks if the user agent is allowed to fetch the URL according to robots.txt."""
    try:
        return parser.can_fetch(MY_USER_AGENT, url)
    except Exception as e:
        logging.error(f"Error during can_fetch check for {url}: {e}. Assuming disallowed.")
        return False

def apply_rate_limit(parser, netloc):
    """Waits if necessary to respect crawl delays."""
    last_accessed = domain_last_accessed.get(netloc, 0)
    now = time.monotonic()
    time_since_last_access = now - last_accessed

    crawl_delay = DEFAULT_DELAY
    try:
        # Respect Crawl-delay directive if present
        delay_from_robots = parser.crawl_delay(MY_USER_AGENT)
        if delay_from_robots is not None:
            crawl_delay = delay_from_robots
    except Exception as e:
         logging.warning(f"Could not get crawl_delay for {netloc}: {e}. Using default {DEFAULT_DELAY}s.")


    wait_time = crawl_delay - time_since_last_access
    if wait_time > 0:
        logging.info(f"Rate limiting {netloc}: Waiting {wait_time:.2f}s (Crawl-delay: {crawl_delay}s)")
        time.sleep(wait_time)

    # Update last accessed time AFTER waiting and BEFORE making the request
    domain_last_accessed[netloc] = time.monotonic()


# --- Main Crawling Loop ---
pages_fetched = 0
logging.info(f"Starting crawl from: {INITIAL_URLS}")
logging.info(f"Allowed domains: {ALLOWED_DOMAINS}")
logging.info(f"Max pages: {MAX_PAGES}")
logging.info(f"User Agent: {MY_USER_AGENT}")
logging.info("-" * 30)

while urls_to_visit and pages_fetched < MAX_PAGES:
    current_url = urls_to_visit.popleft()

    # --- Normalize URL before checking visited ---
    # (Technically, we should normalize before adding to queue too,
    # but doing it here catches initial seeds and prevents some duplication)
    normalized_current_url = normalize_url(current_url, current_url) # Normalize itself
    if not normalized_current_url:
        logging.warning(f"Could not normalize/invalid scheme: {current_url}. Skipping.")
        continue

    if normalized_current_url in visited_urls:
        # logging.info(f"Skipping already processed or queued URL: {normalized_current_url}") # Can be noisy
        continue

    # Mark as visited early to prevent adding same normalized URL again from links
    visited_urls.add(normalized_current_url)

    parsed_url = urlparse(normalized_current_url)
    domain = parsed_url.netloc

    # --- robots.txt Check ---
    robot_parser = get_robot_parser(normalized_current_url)
    if not can_fetch_url(robot_parser, normalized_current_url):
        logging.info(f"Disallowed by robots.txt: {normalized_current_url}")
        continue

    # --- Rate Limiting ---
    apply_rate_limit(robot_parser, domain)

    # --- Fetching ---
    logging.info(f"[{pages_fetched + 1}/{MAX_PAGES}] Fetching: {normalized_current_url}")
    try:
        response = requests.get(normalized_current_url, headers={'User-Agent': MY_USER_AGENT}, timeout=REQUEST_TIMEOUT)
        response.raise_for_status() # Check for 4xx/5xx client/server errors

        # --- Basic Content Type Check ---
        content_type = response.headers.get('Content-Type', '').lower()
        if 'text/html' not in content_type:
            logging.info(f"Skipping non-HTML content ({content_type}) at: {normalized_current_url}")
            continue

        pages_fetched += 1 # Increment only on successful HTML fetch

        # --- Duplicate Content Detection (Basic Hashing) ---
        content_hash = hashlib.sha256(response.content).hexdigest()
        if content_hash in visited_content_hashes:
            logging.info(f"Skipping duplicate content (hash match) at: {normalized_current_url}")
            continue
        visited_content_hashes.add(content_hash)

        # --- Parsing and Data Extraction ---
        soup = BeautifulSoup(response.content, 'lxml') # Use response.content for correct encoding handling

        title = soup.title.string if soup.title else 'No Title Found'
        logging.info(f"  Title: {title.strip()}")

        # TODO: Extract relevant text/data needed for your search engine index here
        # Example: Extract all paragraph text
        # all_text = ' '.join(p.get_text(strip=True) for p in soup.find_all('p'))
        # Send URL, title, all_text, etc. to your database or indexer

        # --- Link Extraction and Frontier Update ---
        for link in soup.find_all('a', href=True):
            normalized_link_url = normalize_url(normalized_current_url, link['href'])

            if normalized_link_url:
                parsed_link_url = urlparse(normalized_link_url)
                # Check scope, visited status, and scheme again before adding
                if (parsed_link_url.netloc in ALLOWED_DOMAINS and
                        normalized_link_url not in visited_urls and
                        normalized_link_url not in urls_to_visit and # Check queue too
                        parsed_link_url.scheme in ['http', 'https']):
                    # logging.info(f"  Adding to queue: {normalized_link_url}") # Can be noisy
                    urls_to_visit.append(normalized_link_url)
                    visited_urls.add(normalized_link_url) # Add to visited when adding to queue

    # --- Specific Error Handling ---
    except requests.exceptions.Timeout:
        logging.warning(f"Timeout fetching {normalized_current_url}")
    except requests.exceptions.ConnectionError:
        logging.warning(f"Connection error fetching {normalized_current_url}")
    except requests.exceptions.HTTPError as e:
        logging.warning(f"HTTP error {e.response.status_code} fetching {normalized_current_url}")
    except requests.exceptions.RequestException as e:
        logging.error(f"Request exception fetching {normalized_current_url}: {e}")
    except Exception as e:
        logging.error(f"Unexpected error processing {normalized_current_url}: {e}", exc_info=True) # Log traceback

# --- Crawl End ---
logging.info("-" * 30)
logging.info(f"Crawl finished. Successfully fetched {pages_fetched} pages.")
logging.info(f"Total unique URLs encountered (visited or queued): {len(visited_urls)}")
logging.info(f"URLs remaining in queue: {len(urls_to_visit)}")
logging.info(f"Unique content hashes processed: {len(visited_content_hashes)}")