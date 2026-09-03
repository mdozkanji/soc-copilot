"""
Ad-hoc search_mitre queries from the command line.

Usage:
    python -m soc_copilot.rag.cli "encoded PowerShell command execution"
    python -m soc_copilot.rag.cli --backend chroma "..."   # needs sentence-transformers installed
"""

from __future__ import annotations

import argparse
import json

from soc_copilot.rag.mitre_loader import load_techniques
from soc_copilot.rag.tfidf_retriever import TfidfRetriever


def main() -> None:
    parser = argparse.ArgumentParser(description="Query the MITRE ATT&CK retriever directly.")
    parser.add_argument("query", help="Free-text description of observed behavior.")
    parser.add_argument("-k", type=int, default=5, help="Number of results (default 5).")
    parser.add_argument(
        "--backend",
        choices=["tfidf", "chroma"],
        default="tfidf",
        help="Retrieval backend. 'chroma' requires `pip install -e '.[embeddings]'` and network access to "
        "huggingface.co on first run to download the embedding model -- not available from the sandbox "
        "this project was built in, so only 'tfidf' has been verified end-to-end so far.",
    )
    args = parser.parse_args()

    techniques = load_techniques()
    if args.backend == "tfidf":
        retriever = TfidfRetriever(techniques)
    else:
        from soc_copilot.rag.chroma_retriever import ChromaRetriever

        retriever = ChromaRetriever()
        retriever.index(techniques)

    results = retriever.search(args.query, k=args.k)
    print(json.dumps([json.loads(r.model_dump_json()) for r in results], indent=2))


if __name__ == "__main__":
    main()
