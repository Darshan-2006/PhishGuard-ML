import ipaddress
import re
from bs4 import BeautifulSoup
import requests
import whois
from datetime import datetime
from urllib.parse import urlparse

# Optional dependency: googlesearch
try:
    from googlesearch import search
except Exception:  # pragma: no cover
    search = None


class FeatureExtraction:
    def __init__(self, url):
        self.features = []
        self.url = url
        self.domain = ""
        self.whois_response = None
        self.urlparse = None
        self.response = None
        self.soup = None

        # Fetch HTML (best-effort)
        try:
            self.response = requests.get(url, timeout=10)
            self.soup = BeautifulSoup(self.response.text, "html.parser")
        except Exception:
            self.response = None
            self.soup = BeautifulSoup("", "html.parser")

        # Parse URL domain (best-effort)
        try:
            self.urlparse = urlparse(url)
            self.domain = self.urlparse.netloc or ""
        except Exception:
            self.urlparse = None
            self.domain = ""

        # WHOIS (best-effort)
        try:
            if self.domain:
                self.whois_response = whois.whois(self.domain)
        except Exception:
            self.whois_response = None

        # 30 features (each returns -1/0/1)
        self.features.append(self.UsingIp())
        self.features.append(self.longUrl())
        self.features.append(self.shortUrl())
        self.features.append(self.symbol())
        self.features.append(self.redirecting())
        self.features.append(self.prefixSuffix())
        self.features.append(self.SubDomains())
        self.features.append(self.Hppts())
        self.features.append(self.DomainRegLen())
        self.features.append(self.Favicon())

        self.features.append(self.NonStdPort())
        self.features.append(self.HTTPSDomainURL())
        self.features.append(self.RequestURL())
        self.features.append(self.AnchorURL())
        self.features.append(self.LinksInScriptTags())
        self.features.append(self.ServerFormHandler())
        self.features.append(self.InfoEmail())
        self.features.append(self.AbnormalURL())
        self.features.append(self.WebsiteForwarding())
        self.features.append(self.StatusBarCust())

        self.features.append(self.DisableRightClick())
        self.features.append(self.UsingPopupWindow())
        self.features.append(self.IframeRedirection())
        self.features.append(self.AgeofDomain())
        self.features.append(self.DNSRecording())
        self.features.append(self.WebsiteTraffic())
        self.features.append(self.PageRank())
        self.features.append(self.GoogleIndex())
        self.features.append(self.LinksPointingToPage())
        self.features.append(self.StatsReport())

    # 1.UsingIp
    def UsingIp(self):
        try:
            ipaddress.ip_address(self.url)
            return -1
        except Exception:
            return 1

    # 2.longUrl
    def longUrl(self):
        if len(self.url) < 54:
            return 1
        if 54 <= len(self.url) <= 75:
            return 0
        return -1

    # 3.shortUrl
    def shortUrl(self):
        try:
            match = re.search(
                r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|"
                r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|"
                r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|"
                r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|"
                r"db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|"
                r"q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|"
                r"x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|"
                r"link\.zip\.net",
                self.url,
            )
            return -1 if match else 1
        except Exception:
            return -1

    # 4.Symbol@
    def symbol(self):
        try:
            return -1 if "@" in self.url else 1
        except Exception:
            return -1

    # 5.Redirecting//
    def redirecting(self):
        try:
            return -1 if self.url.rfind("//") > 6 else 1
        except Exception:
            return -1

    # 6.prefixSuffix
    def prefixSuffix(self):
        try:
            return -1 if re.findall(r"\-", self.domain) else 1
        except Exception:
            return -1

    # 7.SubDomains
    def SubDomains(self):
        try:
            dot_count = len(re.findall(r"\.", self.url))
            if dot_count == 1:
                return 1
            if dot_count == 2:
                return 0
            return -1
        except Exception:
            return -1

    # 8.HTTPS
    def Hppts(self):
        try:
            scheme = self.urlparse.scheme if self.urlparse else ""
            return 1 if "https" in scheme else -1
        except Exception:
            return 1

    # 9.DomainRegLen
    def DomainRegLen(self):
        try:
            if not self.whois_response:
                return -1
            expiration_date = self.whois_response.expiration_date
            creation_date = self.whois_response.creation_date
            try:
                if isinstance(expiration_date, list):
                    expiration_date = expiration_date[0]
            except Exception:
                pass
            try:
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
            except Exception:
                pass

            age = (expiration_date.year - creation_date.year) * 12 + (
                expiration_date.month - creation_date.month
            )
            return 1 if age >= 12 else -1
        except Exception:
            return -1

    # 10. Favicon
    def Favicon(self):
        try:
            if not self.soup:
                return -1
            for head in self.soup.find_all("head"):
                for link in self.soup.find_all("link", href=True):
                    dots = [x.start(0) for x in re.finditer(r"\.", link['href'])]
                    if self.url in link['href'] or len(dots) == 1 or self.domain in link['href']:
                        return 1
            return -1
        except Exception:
            return -1

    # 11. NonStdPort
    def NonStdPort(self):
        try:
            parts = self.domain.split(":") if self.domain else []
            return -1 if len(parts) > 1 else 1
        except Exception:
            return -1

    # 12. HTTPSDomainURL
    def HTTPSDomainURL(self):
        try:
            return -1 if "https" in self.domain else 1
        except Exception:
            return -1

    # 13. RequestURL
    def RequestURL(self):
        try:
            html = self.response.text if self.response else ""
            success = 0
            i = 0

            def count(tag, attr):
                nonlocal success, i
                try:
                    elems = self.soup.find_all(tag, **{attr: True})
                    for e in elems:
                        src = e.get(attr, "")
                        dots = [x.start(0) for x in re.finditer(r"\.", src)]
                        if self.url in src or self.domain in src or len(dots) == 1:
                            success += 1
                        i += 1
                except Exception:
                    pass

            count("img", "src")
            count("audio", "src")
            count("embed", "src")
            count("iframe", "src")

            if i == 0:
                return -1

            percentage = success / float(i) * 100
            if percentage < 22.0:
                return 1
            if 22.0 <= percentage < 61.0:
                return 0
            return -1
        except Exception:
            return -1

    # 14. AnchorURL
    def AnchorURL(self):
        try:
            i = 0
            unsafe = 0
            for a in self.soup.find_all("a", href=True):
                if self.url in a["href"] or self.domain in a["href"]:
                    unsafe += 1
                i += 1
            if i == 0:
                return -1
            percentage = unsafe / float(i) * 100
            if percentage < 31.0:
                return 1
            if 31.0 <= percentage < 67.0:
                return 0
            return -1
        except Exception:
            return -1

    # 15. LinksInScriptTags
    def LinksInScriptTags(self):
        try:
            i = 0
            success = 0

            for link in self.soup.find_all("link", href=True):
                dots = [x.start(0) for x in re.finditer(r"\.", link['href'])]
                if self.url in link['href'] or self.domain in link['href'] or len(dots) == 1:
                    success += 1
                i += 1

            for script in self.soup.find_all("script", src=True):
                dots = [x.start(0) for x in re.finditer(r"\.", script['src'])]
                if self.url in script['src'] or self.domain in script['src'] or len(dots) == 1:
                    success += 1
                i += 1

            if i == 0:
                return -1

            percentage = success / float(i) * 100
            if percentage < 17.0:
                return 1
            if 17.0 <= percentage < 81.0:
                return 0
            return -1
        except Exception:
            return -1

    # 16. ServerFormHandler
    def ServerFormHandler(self):
        try:
            for form in self.soup.find_all("form", action=True):
                action = form.get("action", "")
                if action in ("", "about:blank"):
                    return -1
                if self.url not in action and self.domain not in action:
                    return 0
                return 1
            return 1
        except Exception:
            return -1

    # 17. InfoEmail
    def InfoEmail(self):
        try:
            txt = self.response.text if self.response else ""
            return -1 if re.findall(r"[mail\(\)|mailto:]", txt) else 1
        except Exception:
            return -1

    # 18. AbnormalURL
    def AbnormalURL(self):
        try:
            txt = self.response.text if self.response else ""
            return 1 if txt == self.whois_response else -1
        except Exception:
            return -1

    # 19. WebsiteForwarding
    def WebsiteForwarding(self):
        try:
            if not self.response:
                return -1
            hist_len = len(getattr(self.response, "history", []) or [])
            if hist_len <= 1:
                return 1
            if hist_len <= 4:
                return 0
            return -1
        except Exception:
            return -1

    # 20. StatusBarCust
    def StatusBarCust(self):
        try:
            txt = self.response.text if self.response else ""
            return -1 if re.findall(r"<script>.+onmouseover.+</script>", txt) else 1
        except Exception:
            return -1

    # 21. DisableRightClick
    def DisableRightClick(self):
        try:
            txt = self.response.text if self.response else ""
            return -1 if re.findall(r"event.button ?== ?2", txt) else 1
        except Exception:
            return -1

    # 22. UsingPopupWindow
    def UsingPopupWindow(self):
        try:
            txt = self.response.text if self.response else ""
            return -1 if re.findall(r"alert\(", txt) else 1
        except Exception:
            return -1

    # 23. IframeRedirection
    def IframeRedirection(self):
        try:
            txt = self.response.text if self.response else ""
            return -1 if re.findall(r"<iframe>", txt) else 1
        except Exception:
            return -1

    # 24. AgeofDomain
    def AgeofDomain(self):
        try:
            if not self.whois_response:
                return -1
            creation_date = self.whois_response.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            age = (datetime.now() - creation_date).days
            return 1 if age >= 180 else -1
        except Exception:
            return -1

    # 25. DNSRecording
    def DNSRecording(self):
        try:
            if self.whois_response and getattr(self.whois_response, "domain_name", None):
                return 1
            return -1
        except Exception:
            return -1

    # 26. WebsiteTraffic
    def WebsiteTraffic(self):
        try:
            # Alexa endpoint (best-effort; may fail)
            url = f"http://data.alexa.com/data?cli=10&dat=s&url={self.url}"
            text = requests.get(url, timeout=10).text
            reach = BeautifulSoup(text, "xml").find("REACH")
            rank = int(reach["RANK"]) if reach and reach.has_attr("RANK") else 0
            return 1 if rank < 100000 else 0
        except Exception:
            return -1

    # 27. PageRank
    def PageRank(self):
        try:
            params = {"name": self.domain}
            text = requests.get(
                "https://www.checkpagerank.net/index.php", params=params, timeout=10
            ).text
            pagerank_text = (
                BeautifulSoup(text, "html.parser")
                .find("div", class_="prnew")
                .get_text(strip=True)
            )
            pagerank = int(pagerank_text)
            if 0 < pagerank < 10:
                return 1
            if pagerank == 0:
                return 0
            return -1
        except Exception:
            return -1

    # 28. GoogleIndex
    def GoogleIndex(self):
        try:
            if not search:
                return -1
            sites = search(self.url, 5)
            return 1 if sites else -1
        except Exception:
            return -1

    # 29. LinksPointingToPage
    def LinksPointingToPage(self):
        try:
            count = len(self.soup.find_all("a"))
            if count == 0:
                return -1
            if count <= 2:
                return 0
            return 1
        except Exception:
            return -1

    # 30. StatsReport
    def StatsReport(self):
        try:
            txt = self.response.text if self.response else ""
            url_match = re.findall(
                r"//www\.phishtank\.com/phish_detail\.php\?phish_id=\d+", txt
            )
            return -1 if url_match else 1
        except Exception:
            return -1

    def getFeaturesList(self):
        return self.features

    def getFeatureDetails(self):
        feature_names = [
            "UsingIp",
            "longUrl",
            "shortUrl",
            "symbol",
            "redirecting",
            "prefixSuffix",
            "SubDomains",
            "Hppts",
            "DomainRegLen",
            "Favicon",
            "NonStdPort",
            "HTTPSDomainURL",
            "RequestURL",
            "AnchorURL",
            "LinksInScriptTags",
            "ServerFormHandler",
            "InfoEmail",
            "AbnormalURL",
            "WebsiteForwarding",
            "StatusBarCust",
            "DisableRightClick",
            "UsingPopupWindow",
            "IframeRedirection",
            "AgeofDomain",
            "DNSRecording",
            "WebsiteTraffic",
            "PageRank",
            "GoogleIndex",
            "LinksPointingToPage",
            "StatsReport",
        ]
        return dict(zip(feature_names, self.features))

