# 🕷️ Simple Web Crawler (written in Python)

This is a simple web crawler built with Python. It takes a starting URL and crawls web pages by following hyperlinks, collecting page titles and URLs. The project is intended for learning purposes and demonstrates how to fetch and parse HTML content using standard Python libraries.

## 📦 Features

- Recursively visits internal links on a website  
- Extracts and prints page titles and URLs  
- Basic filtering to avoid duplicate visits  
- Simple depth-limiting to control crawl size  

## 🛠️ Technologies Used

- Python 3  
- `requests` for HTTP requests  
- `BeautifulSoup` (from `bs4`) for HTML parsing  
- `urllib.parse` for URL resolution  

## 🚀 Getting Started

### Prerequisites

Make sure you have Python 3 installed. Then install the required dependencies:

```bash
pip install requests beautifulsoup4
