"""Web research tools for CTF writeups, vulnerability notes, and docs."""
from __future__ import annotations

import html
import json
import os
import re
from html.parser import HTMLParser
from typing import Any
from urllib.parse import parse_qs, quote_plus, unquote, urlparse

import httpx

from hacking_agent.core.events import emit


DEFAULT_TIMEOUT = 20.0
MAX_FETCH_CHARS = 12000


class _DuckResultParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.results: list[dict[str, str]] = []
        self._in_link = False
        self._href = ""
        self._text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_dict = {k: v or "" for k, v in attrs}
        if tag == "a" and "result__a" in attrs_dict.get("class", ""):
            self._in_link = True
            self._href = attrs_dict.get("href", "")
            self._text = []

    def handle_data(self, data: str) -> None:
        if self._in_link:
            self._text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == "a" and self._in_link:
            title = html.unescape(" ".join(self._text)).strip()
            url = _unwrap_duck_url(self._href)
            if title and url:
                self.results.append({"title": title, "url": url, "snippet": ""})
            self._in_link = False


class _TextExtractor(HTMLParser):
    SKIP = {"script", "style", "noscript", "svg", "canvas"}

    def __init__(self):
        super().__init__()
        self.title = ""
        self._in_title = False
        self._skip_depth = 0
        self.parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in self.SKIP:
            self._skip_depth += 1
        if tag == "title":
            self._in_title = True
        if tag in {"p", "br", "li", "h1", "h2", "h3", "pre", "code"}:
            self.parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in self.SKIP and self._skip_depth:
            self._skip_depth -= 1
        if tag == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._skip_depth:
            return
        text = html.unescape(data).strip()
        if not text:
            return
        if self._in_title:
            self.title += text
        else:
            self.parts.append(text)

    def text(self) -> str:
        joined = " ".join(self.parts)
        joined = re.sub(r"\s+", " ", joined)
        joined = re.sub(r"\s+\n\s+", "\n", joined)
        return joined.strip()


def _unwrap_duck_url(url: str) -> str:
    if not url:
        return ""
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    if "uddg" in qs:
        return unquote(qs["uddg"][0])
    return url


class WebResearchClient:
    def __init__(self, timeout: float = DEFAULT_TIMEOUT):
        self.timeout = timeout
        self._client = httpx.Client(
            timeout=timeout,
            follow_redirects=True,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 HackingAgentResearch/1.0"
                )
            },
        )

    def search(self, query: str, max_results: int = 8, focus: str = "ctf") -> dict[str, Any]:
        """Search the public web, preferring configured APIs and falling back to DuckDuckGo."""
        query = query.strip()
        max_results = max(1, min(max_results, 20))
        focused_query = self._focus_query(query, focus)
        emit("web_search", {
            "stage": "start",
            "query": focused_query,
            "focus": focus,
            "max_results": max_results,
        })

        providers = []
        if os.getenv("BRAVE_SEARCH_API_KEY"):
            providers.append(("brave", self._brave_search))
        if os.getenv("SERPAPI_API_KEY"):
            providers.append(("serpapi", self._serpapi_search))
        providers.append(("duckduckgo_html", self._duckduckgo_search))

        result: dict[str, Any] | None = None
        last_error = ""
        for provider_name, search_fn in providers:
            try:
                result = search_fn(focused_query, max_results)
                break
            except Exception as exc:
                last_error = str(exc)
                emit("error", {
                    "component": "web_search",
                    "provider": provider_name,
                    "message": last_error,
                })

        if result is None:
            result = {
                "provider": "none",
                "query": focused_query,
                "results": [],
                "error": f"all search providers failed: {last_error}",
            }

        emit("web_search", {
            "stage": "complete",
            "query": focused_query,
            "focus": focus,
            "count": len(result.get("results", [])),
            "provider": result.get("provider"),
        })
        return result

    def fetch(self, url: str, max_chars: int = MAX_FETCH_CHARS) -> dict[str, Any]:
        max_chars = max(1000, min(max_chars, 50000))
        emit("web_fetch", {"stage": "start", "url": url})
        try:
            resp = self._client.get(url)
            content_type = resp.headers.get("content-type", "")
            if "text/html" in content_type:
                parser = _TextExtractor()
                parser.feed(resp.text)
                text = parser.text()
                title = parser.title.strip()
            else:
                title = ""
                text = resp.text
            output = {
                "url": str(resp.url),
                "status_code": resp.status_code,
                "content_type": content_type,
                "title": title,
                "text": text[:max_chars],
                "truncated": len(text) > max_chars,
            }
            emit("web_fetch", {
                "stage": "complete",
                "url": url,
                "status_code": resp.status_code,
                "title": title,
                "chars": min(len(text), max_chars),
            })
            return output
        except httpx.HTTPError as exc:
            err = {"error": f"fetch failed: {exc}", "url": url}
            emit("error", {"component": "web_fetch", "message": str(exc), "url": url})
            return err

    def _focus_query(self, query: str, focus: str) -> str:
        if focus == "ctf":
            return f"{query} CTF writeup walkthrough exploit"
        if focus == "vuln":
            return f"{query} vulnerability CVE exploit advisory"
        if focus == "docs":
            return f"{query} official documentation security"
        return query

    def _brave_search(self, query: str, max_results: int) -> dict[str, Any]:
        resp = self._client.get(
            "https://api.search.brave.com/res/v1/web/search",
            params={"q": query, "count": max_results},
            headers={
                "Accept": "application/json",
                "X-Subscription-Token": os.getenv("BRAVE_SEARCH_API_KEY", ""),
            },
        )
        resp.raise_for_status()
        data = resp.json()
        results = []
        for item in data.get("web", {}).get("results", [])[:max_results]:
            results.append({
                "title": item.get("title", ""),
                "url": item.get("url", ""),
                "snippet": item.get("description", ""),
            })
        return {"provider": "brave", "query": query, "results": results}

    def _serpapi_search(self, query: str, max_results: int) -> dict[str, Any]:
        resp = self._client.get(
            "https://serpapi.com/search.json",
            params={"engine": "google", "q": query, "api_key": os.getenv("SERPAPI_API_KEY")},
        )
        resp.raise_for_status()
        data = resp.json()
        results = []
        for item in data.get("organic_results", [])[:max_results]:
            results.append({
                "title": item.get("title", ""),
                "url": item.get("link", ""),
                "snippet": item.get("snippet", ""),
            })
        return {"provider": "serpapi", "query": query, "results": results}

    def _duckduckgo_search(self, query: str, max_results: int) -> dict[str, Any]:
        resp = self._client.get(
            "https://duckduckgo.com/html/",
            params={"q": query},
            headers={"Accept": "text/html,application/xhtml+xml"},
        )
        resp.raise_for_status()
        parser = _DuckResultParser()
        parser.feed(resp.text)
        results = parser.results[:max_results]
        return {"provider": "duckduckgo_html", "query": query, "results": results}


_client: WebResearchClient | None = None


def get_client() -> WebResearchClient:
    global _client
    if _client is None:
        _client = WebResearchClient()
    return _client


def web_search(query: str, max_results: int = 8, focus: str = "ctf") -> str:
    return json.dumps(get_client().search(query, max_results, focus), indent=2)


def web_fetch(url: str, max_chars: int = MAX_FETCH_CHARS) -> str:
    return json.dumps(get_client().fetch(url, max_chars), indent=2)
