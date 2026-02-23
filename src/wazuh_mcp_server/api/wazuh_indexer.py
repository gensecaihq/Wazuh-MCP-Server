"""
Wazuh Indexer client for alert and vulnerability queries.

Wazuh stores alerts and vulnerability data in the Wazuh Indexer
(Elasticsearch/OpenSearch), not the Manager API. This client queries:
  - wazuh-alerts-* — alert data (alerts have never had a Manager API endpoint)
  - wazuh-states-vulnerabilities-* — vulnerability data (removed from Manager API in 4.8.0)
"""

import logging
from typing import Any, Dict, Optional

import httpx
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

logger = logging.getLogger(__name__)

# Index patterns for Wazuh 4.x
ALERTS_INDEX = "wazuh-alerts-*"
VULNERABILITY_INDEX = "wazuh-states-vulnerabilities-*"


class WazuhIndexerClient:
    """
    Client for querying the Wazuh Indexer (Elasticsearch/OpenSearch).

    Required for vulnerability queries in Wazuh 4.8.0 and later.
    """

    def __init__(
        self,
        host: str,
        port: int = 9200,
        username: Optional[str] = None,
        password: Optional[str] = None,
        verify_ssl: bool = True,
        timeout: int = 30,
    ):
        # Normalize host (strip protocol if user included it)
        self.host = self._normalize_host(host)
        self.port = port
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.client: Optional[httpx.AsyncClient] = None
        self._initialized = False

    @staticmethod
    def _normalize_host(host: str) -> str:
        """Strip protocol prefix from host if present."""
        if not host:
            return host
        for prefix in ("https://", "http://"):
            if host.lower().startswith(prefix):
                host = host[len(prefix) :]
                break
        return host.rstrip("/")

    @property
    def base_url(self) -> str:
        """Get the base URL for the Wazuh Indexer."""
        return f"https://{self.host}:{self.port}"

    async def initialize(self):
        """Initialize the HTTP client."""
        auth = None
        if self.username and self.password:
            auth = (self.username, self.password)

        self.client = httpx.AsyncClient(verify=self.verify_ssl, timeout=self.timeout, auth=auth)
        self._initialized = True
        logger.info(f"WazuhIndexerClient initialized for {self.host}:{self.port}")

    async def close(self):
        """Close the HTTP client."""
        if self.client:
            await self.client.aclose()
            self._initialized = False

    async def _ensure_initialized(self):
        """Ensure client is initialized."""
        if not self._initialized:
            await self.initialize()

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        retry=retry_if_exception_type((httpx.RequestError, httpx.HTTPStatusError)),
        reraise=True,
    )
    async def _search(self, index: str, query: Dict[str, Any], size: int = 100) -> Dict[str, Any]:
        """
        Execute a search query against the Wazuh Indexer.

        Args:
            index: Index pattern to search
            query: Elasticsearch query DSL
            size: Maximum number of results

        Returns:
            Search results from the indexer
        """
        await self._ensure_initialized()

        url = f"{self.base_url}/{index}/_search"
        body = {"query": query, "size": size}

        try:
            response = await self.client.post(url, json=body, headers={"Content-Type": "application/json"})
            response.raise_for_status()
            return response.json()

        except httpx.HTTPStatusError as e:
            logger.error(f"Indexer search failed: {e.response.status_code} - {e.response.text}")
            raise ValueError(f"Indexer query failed: {e.response.status_code}")
        except httpx.ConnectError:
            raise ConnectionError(f"Cannot connect to Wazuh Indexer at {self.host}:{self.port}")
        except httpx.TimeoutException:
            raise ConnectionError(f"Timeout connecting to Wazuh Indexer at {self.host}:{self.port}")

    async def get_alerts(
        self,
        limit: int = 100,
        rule_id: Optional[str] = None,
        level: Optional[str] = None,
        agent_id: Optional[str] = None,
        timestamp_start: Optional[str] = None,
        timestamp_end: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Get alerts from the Wazuh Indexer (wazuh-alerts-* index).

        Args:
            limit: Maximum number of results
            rule_id: Filter by rule ID
            level: Minimum rule level (severity)
            agent_id: Filter by agent ID
            timestamp_start: Start of time range (ISO 8601)
            timestamp_end: End of time range (ISO 8601)

        Returns:
            Alert data in standard Wazuh format
        """
        await self._ensure_initialized()

        # Build bool query with must clauses for each non-empty filter
        must_clauses: list = []

        if rule_id:
            must_clauses.append({"match": {"rule.id": rule_id}})

        if agent_id:
            must_clauses.append({"match": {"agent.id": agent_id}})

        if level:
            # level is a minimum severity threshold (e.g. "10" means level >= 10)
            try:
                min_level = int(level.rstrip("+"))
                must_clauses.append({"range": {"rule.level": {"gte": min_level}}})
            except (ValueError, AttributeError):
                pass

        if timestamp_start or timestamp_end:
            time_range: Dict[str, str] = {}
            if timestamp_start:
                time_range["gte"] = timestamp_start
            if timestamp_end:
                time_range["lte"] = timestamp_end
            must_clauses.append({"range": {"timestamp": time_range}})

        if must_clauses:
            query = {"bool": {"must": must_clauses}}
        else:
            query = {"match_all": {}}

        # Build the full search body with sort by timestamp desc
        url = f"{self.base_url}/{ALERTS_INDEX}/_search"
        body = {
            "query": query,
            "size": limit,
            "sort": [{"timestamp": {"order": "desc"}}],
        }

        try:
            response = await self.client.post(url, json=body, headers={"Content-Type": "application/json"})
            response.raise_for_status()
            result = response.json()
        except httpx.HTTPStatusError as e:
            logger.error(f"Alerts query failed: {e.response.status_code} - {e.response.text}")
            raise ValueError(f"Alerts query failed: {e.response.status_code}")
        except httpx.ConnectError:
            raise ConnectionError(f"Cannot connect to Wazuh Indexer at {self.host}:{self.port}")
        except httpx.TimeoutException:
            raise ConnectionError(f"Timeout connecting to Wazuh Indexer at {self.host}:{self.port}")

        # Transform to standard Wazuh format
        hits = result.get("hits", {})
        alerts = [hit.get("_source", {}) for hit in hits.get("hits", [])]

        return {
            "data": {
                "affected_items": alerts,
                "total_affected_items": hits.get("total", {}).get("value", len(alerts)),
                "total_failed_items": 0,
                "failed_items": [],
            }
        }

    async def get_vulnerabilities(
        self,
        agent_id: Optional[str] = None,
        severity: Optional[str] = None,
        cve_id: Optional[str] = None,
        limit: int = 100,
    ) -> Dict[str, Any]:
        """
        Get vulnerabilities from the Wazuh Indexer.

        Args:
            agent_id: Filter by agent ID
            severity: Filter by severity (Critical, High, Medium, Low)
            cve_id: Filter by specific CVE ID
            limit: Maximum number of results

        Returns:
            Vulnerability data matching the criteria
        """
        # Build query
        must_clauses = []

        if agent_id:
            must_clauses.append({"match": {"agent.id": agent_id}})

        if severity:
            # Normalize severity to match indexer format
            severity_normalized = severity.capitalize()
            must_clauses.append({"match": {"vulnerability.severity": severity_normalized}})

        if cve_id:
            must_clauses.append({"match": {"vulnerability.id": cve_id}})

        # Build the query
        if must_clauses:
            query = {"bool": {"must": must_clauses}}
        else:
            query = {"match_all": {}}

        result = await self._search(VULNERABILITY_INDEX, query, size=limit)

        # Transform to standard format
        hits = result.get("hits", {})
        vulnerabilities = []

        for hit in hits.get("hits", []):
            source = hit.get("_source", {})
            vulnerabilities.append(
                {
                    "id": source.get("vulnerability", {}).get("id"),
                    "severity": source.get("vulnerability", {}).get("severity"),
                    "description": source.get("vulnerability", {}).get("description"),
                    "reference": source.get("vulnerability", {}).get("reference"),
                    "status": source.get("vulnerability", {}).get("status"),
                    "detected_at": source.get("vulnerability", {}).get("detected_at"),
                    "published_at": source.get("vulnerability", {}).get("published_at"),
                    "agent": {
                        "id": source.get("agent", {}).get("id"),
                        "name": source.get("agent", {}).get("name"),
                    },
                    "package": {
                        "name": source.get("package", {}).get("name"),
                        "version": source.get("package", {}).get("version"),
                        "architecture": source.get("package", {}).get("architecture"),
                    },
                }
            )

        return {
            "data": {
                "affected_items": vulnerabilities,
                "total_affected_items": hits.get("total", {}).get("value", len(vulnerabilities)),
                "total_failed_items": 0,
                "failed_items": [],
            }
        }

    async def get_critical_vulnerabilities(self, limit: int = 50) -> Dict[str, Any]:
        """
        Get critical severity vulnerabilities.

        Args:
            limit: Maximum number of results

        Returns:
            Critical vulnerability data
        """
        return await self.get_vulnerabilities(severity="Critical", limit=limit)

    async def get_vulnerability_summary(self) -> Dict[str, Any]:
        """
        Get vulnerability summary statistics.

        Returns:
            Summary with counts by severity
        """
        await self._ensure_initialized()

        # Aggregation query for severity counts
        url = f"{self.base_url}/{VULNERABILITY_INDEX}/_search"
        body = {
            "size": 0,
            "aggs": {
                "by_severity": {"terms": {"field": "vulnerability.severity", "size": 10}},
                "by_agent": {"cardinality": {"field": "agent.id"}},
                "total_vulnerabilities": {"value_count": {"field": "vulnerability.id"}},
            },
        }

        try:
            response = await self.client.post(url, json=body, headers={"Content-Type": "application/json"})
            response.raise_for_status()
            result = response.json()

            # Parse aggregations
            aggs = result.get("aggregations", {})
            severity_buckets = aggs.get("by_severity", {}).get("buckets", [])

            severity_counts = {}
            for bucket in severity_buckets:
                severity_counts[bucket.get("key", "unknown")] = bucket.get("doc_count", 0)

            return {
                "data": {
                    "total_vulnerabilities": aggs.get("total_vulnerabilities", {}).get("value", 0),
                    "affected_agents": aggs.get("by_agent", {}).get("value", 0),
                    "by_severity": severity_counts,
                    "critical": severity_counts.get("Critical", 0),
                    "high": severity_counts.get("High", 0),
                    "medium": severity_counts.get("Medium", 0),
                    "low": severity_counts.get("Low", 0),
                }
            }

        except httpx.HTTPStatusError as e:
            logger.error(f"Vulnerability summary query failed: {e.response.status_code}")
            raise ValueError(f"Vulnerability summary query failed: {e.response.status_code}")
        except httpx.ConnectError:
            raise ConnectionError(f"Cannot connect to Wazuh Indexer at {self.host}:{self.port}")

    async def health_check(self) -> Dict[str, Any]:
        """
        Check Wazuh Indexer health status.

        Returns:
            Health status information
        """
        await self._ensure_initialized()

        try:
            response = await self.client.get(f"{self.base_url}/_cluster/health")
            response.raise_for_status()
            health = response.json()

            return {
                "status": health.get("status"),
                "cluster_name": health.get("cluster_name"),
                "number_of_nodes": health.get("number_of_nodes"),
                "active_shards": health.get("active_shards"),
            }

        except Exception as e:
            return {"status": "unavailable", "error": str(e)}


class IndexerNotConfiguredError(Exception):
    """Raised when Wazuh Indexer is not configured but required."""

    def __init__(self, message: str = None):
        default_message = (
            "Wazuh Indexer not configured. "
            "Alert and vulnerability tools require the Wazuh Indexer.\n\n"
            "Please set the following environment variables:\n"
            "  WAZUH_INDEXER_HOST=<indexer_hostname>\n"
            "  WAZUH_INDEXER_USER=<indexer_username>\n"
            "  WAZUH_INDEXER_PASS=<indexer_password>\n"
            "  WAZUH_INDEXER_PORT=9200 (optional, default: 9200)\n\n"
            "Note: The /vulnerability API was removed in Wazuh 4.8.0. "
            "Vulnerability data must be queried from the Wazuh Indexer."
        )
        super().__init__(message or default_message)
