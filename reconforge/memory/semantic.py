"""
ReconForge Semantic Memory — ChromaDB-backed vector store for RAG.

Collections:
1. cve_database   - CVE descriptions, CVSS scores, affected versions
2. exploit_refs   - PoC references, ExploitDB IDs
3. past_reports   - Anonymized findings from past missions
4. tool_knowledge - Usage guides, parsing hints per tool
"""

import json
import os
from pathlib import Path
from typing import Optional

import chromadb
from chromadb.config import Settings

from reconforge.utils.logger import get_logger

logger = get_logger("semantic_memory")

COLLECTIONS = ["cve_database", "exploit_refs", "past_reports", "tool_knowledge", "cross_mission_intel"]


class SemanticMemory:
    """
    ChromaDB-backed vector store. Provides RAG-style retrieval
    for CVE lookups, exploit references, and past mission knowledge.
    """

    def __init__(self, persist_dir: Optional[str] = None) -> None:
        if persist_dir is None:
            persist_dir = str(Path(os.environ.get("HOME", "~")).expanduser() / ".gemini" / "antigravity" / "chromadb")
        self.persist_dir = Path(persist_dir)
        self.persist_dir.mkdir(parents=True, exist_ok=True)
        self._client: Optional[chromadb.ClientAPI] = None
        self._collections: dict[str, chromadb.Collection] = {}
        self._initialized = False

    def _ensure_init(self) -> None:
        """Lazy initialization of ChromaDB client and collections."""
        if self._initialized:
            return
        try:
            self._client = chromadb.PersistentClient(
                path=str(self.persist_dir),
                settings=Settings(anonymized_telemetry=False),
            )
            for name in COLLECTIONS:
                self._collections[name] = self._client.get_or_create_collection(
                    name=name,
                    metadata={"hnsw:space": "cosine"},
                )
            self._initialized = True
            logger.info(f"SemanticMemory initialized at {self.persist_dir}")
        except Exception as e:
            logger.warning(f"ChromaDB init failed: {e}")
            self._initialized = False

    # ── Query ────────────────────────────────────────────────

    def query(self, text: str, collection: str = "cve_database",
              n_results: int = 5, where: Optional[dict] = None) -> list[dict]:
        """
        Semantic search across a collection.

        Returns list of {id, document, metadata, distance} dicts.
        """
        self._ensure_init()
        if not self._initialized or collection not in self._collections:
            return []

        try:
            coll = self._collections[collection]
            kwargs = {"query_texts": [text], "n_results": n_results}
            if where:
                kwargs["where"] = where

            results = coll.query(**kwargs)

            # Flatten ChromaDB's nested structure
            findings = []
            if results and results["ids"] and results["ids"][0]:
                for i, doc_id in enumerate(results["ids"][0]):
                    finding = {
                        "id": doc_id,
                        "document": results["documents"][0][i] if results["documents"] else "",
                        "metadata": results["metadatas"][0][i] if results["metadatas"] else {},
                        "distance": results["distances"][0][i] if results["distances"] else 1.0,
                    }
                    findings.append(finding)

            logger.debug(f"Semantic query '{text[:50]}' returned {len(findings)} results")
            return findings
        except Exception as e:
            logger.warning(f"Semantic query failed: {e}")
            return []

    def query_cves(self, service: str, version: str = "",
                   n_results: int = 10) -> list[dict]:
        """Query CVE database for a specific service + version."""
        query_text = f"{service} {version}".strip()
        results = self.query(query_text, "cve_database", n_results)

        # Filter by relevance (distance < 0.5 means fairly similar)
        return [r for r in results if r.get("distance", 1.0) < 0.5]

    def query_exploits(self, cve_id: str = "", service: str = "",
                       n_results: int = 5) -> list[dict]:
        """Query exploit references for a CVE or service."""
        query_text = cve_id if cve_id else service
        return self.query(query_text, "exploit_refs", n_results)

    def query_past_findings(self, text: str,
                            n_results: int = 5) -> list[dict]:
        """Query past mission reports for similar findings."""
        return self.query(text, "past_reports", n_results)

    # ── Ingest ───────────────────────────────────────────────

    def add_documents(self, collection: str, documents: list[str],
                      metadatas: list[dict], ids: list[str]) -> int:
        """Add documents to a collection. Returns count added."""
        self._ensure_init()
        if not self._initialized or collection not in self._collections:
            return 0

        try:
            coll = self._collections[collection]
            # ChromaDB handles batching internally
            coll.add(documents=documents, metadatas=metadatas, ids=ids)
            logger.info(f"Added {len(documents)} docs to {collection}")
            return len(documents)
        except Exception as e:
            logger.warning(f"Failed to add docs to {collection}: {e}")
            return 0

    def seed_cves(self, nvd_data_path: str) -> int:
        """
        Seed CVE database from NVD JSON feed.

        Expected format: NVD CVE 2.0 JSON (e.g., nvdcve-2.0-*.json)
        """
        self._ensure_init()
        if not self._initialized:
            raise RuntimeError("ChromaDB not initialized")

        path = Path(nvd_data_path)
        if not path.exists():
            raise FileNotFoundError(f"NVD feed not found: {nvd_data_path}")

        with open(path) as f:
            data = json.load(f)

        cve_items = data.get("CVE_Items", data.get("vulnerabilities", []))
        documents = []
        metadatas = []
        ids = []
        batch_size = 500

        for item in cve_items:
            cve_data = item.get("cve", item)
            cve_id = cve_data.get("CVE_data_meta", {}).get("ID",
                     cve_data.get("id", ""))
            if not cve_id:
                continue

            # Extract description
            desc_data = cve_data.get("description", {}).get("description_data",
                        cve_data.get("descriptions", []))
            description = ""
            for d in desc_data:
                if d.get("lang", d.get("language", "")) in ("en", "eng"):
                    description = d.get("value", "")
                    break
            if not description and desc_data:
                description = desc_data[0].get("value", "")

            # Extract CVSS
            impact = item.get("impact", {})
            cvss_v3 = impact.get("baseMetricV3", {}).get("cvssV3", {})
            cvss_v2 = impact.get("baseMetricV2", {}).get("cvssV2", {})
            cvss_score = cvss_v3.get("baseScore", cvss_v2.get("baseScore", 0))
            severity = cvss_v3.get("baseSeverity", "").lower() or (
                "critical" if cvss_score >= 9.0 else
                "high" if cvss_score >= 7.0 else
                "medium" if cvss_score >= 4.0 else "low")

            # Extract affected products (CPE)
            configurations = item.get("configurations", {})
            products = []
            for node in configurations.get("nodes", []):
                for match in node.get("cpe_match", node.get("cpeMatch", [])):
                    uri = match.get("cpe23Uri", match.get("criteria", ""))
                    if uri:
                        parts = uri.split(":")
                        if len(parts) >= 5:
                            products.append(f"{parts[3]}:{parts[4]}")

            doc = f"{cve_id}: {description}"
            meta = {
                "cve_id": cve_id,
                "cvss_score": float(cvss_score) if cvss_score else 0.0,
                "severity": severity,
                "products": ", ".join(products[:10]),
            }

            documents.append(doc)
            metadatas.append(meta)
            ids.append(cve_id)

            # Batch insert
            if len(documents) >= batch_size:
                self.add_documents("cve_database", documents, metadatas, ids)
                documents, metadatas, ids = [], [], []

        # Final batch
        if documents:
            self.add_documents("cve_database", documents, metadatas, ids)

        total = len(cve_items)
        logger.info(f"Seeded {total} CVEs from {nvd_data_path}")
        return total

    def add_report(self, report: str, metadata: dict) -> None:
        """Add a completed mission report for future RAG."""
        self._ensure_init()
        if not self._initialized:
            return

        report_id = metadata.get("mission_id", f"report_{len(report)}")
        # Split report into chunks (~500 chars each)
        chunks = [report[i:i+500] for i in range(0, len(report), 500)]

        documents = []
        metadatas_list = []
        chunk_ids = []

        for i, chunk in enumerate(chunks):
            documents.append(chunk)
            metadatas_list.append({**metadata, "chunk_index": i})
            chunk_ids.append(f"{report_id}_chunk_{i}")

        self.add_documents("past_reports", documents, metadatas_list, chunk_ids)

    def add_tool_knowledge(self, tool_name: str, knowledge: str,
                           metadata: Optional[dict] = None) -> None:
        """Add tool-specific knowledge for RAG."""
        meta = {"tool_name": tool_name, **(metadata or {})}
        self.add_documents("tool_knowledge", [knowledge], [meta],
                           [f"tool_{tool_name}_{hash(knowledge) % 10000}"])

    def ingest_mission_findings(self, intel_store: 'IntelStore', mission_id: str) -> int:
        """Vectorize and store approved findings from a completed mission."""
        self._ensure_init()
        if not self._initialized:
            return 0

        from reconforge.intel.models import (
            OsintFinding,
            SecretFinding,
            Vulnerability,
        )

        findings = []
        for v in intel_store._read_all(Vulnerability, mission_id):
            if v.verified:
                findings.append(v)
        for o in intel_store._read_all(OsintFinding, mission_id):
            if o.verified:
                findings.append(o)
        for s in intel_store._read_all(SecretFinding, mission_id):
            if s.verified or s.is_verified:
                findings.append(s)

        if not findings:
            return 0

        documents = []
        metadatas = []
        ids = []

        for f in findings:
            doc_str = self._finding_to_semantic_document(f)
            documents.append(doc_str)
            metadatas.append({"mission_id": mission_id, "type": type(f).__name__})
            ids.append(f.id)

        return self.add_documents("cross_mission_intel", documents, metadatas, ids)

    def _finding_to_semantic_document(self, finding) -> str:
        """Serialize a finding for vector memory without indexing raw secrets."""
        from reconforge.intel.models import SecretFinding

        if isinstance(finding, SecretFinding):
            safe_data = {
                "type": "SecretFinding",
                "source_agent": finding.source_agent,
                "source_tool": finding.source_tool,
                "host_id": finding.host_id,
                "file_path": finding.file_path,
                "secret_type": finding.secret_type,
                "confidence": finding.confidence,
                "verified": finding.verified,
                "is_verified": finding.is_verified,
            }
            return json.dumps(
                {key: value for key, value in safe_data.items()
                 if value not in (None, "")},
                default=str,
            )

        return json.dumps(
            finding.model_dump(
                exclude={"id", "mission_id", "confidence", "raw_output"},
                mode="json",
            ),
            default=str,
        )

    # ── Stats ────────────────────────────────────────────────

    def get_collection_stats(self) -> dict:
        """Get document counts per collection."""
        self._ensure_init()
        if not self._initialized:
            return {name: 0 for name in COLLECTIONS}

        stats = {}
        for name, coll in self._collections.items():
            try:
                stats[name] = coll.count()
            except Exception:
                stats[name] = 0
        return stats
