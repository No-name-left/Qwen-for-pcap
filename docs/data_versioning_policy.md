# Data versioning policy

GitHub should contain code, RAG knowledge, configs, manifests, hashes, download notes, lightweight scripts, and reports.

Large public data files must stay out of Git by default:

- PCAP, PCAPNG, CAP files
- large flow CSV files
- CTU `*.binetflow` files
- compressed dataset archives
- generated parser outputs and submission artifacts

Dataset synchronization should rely on:

- source URL or official source page;
- local manifest rows;
- file size;
- SHA-256 hash;
- download or manual-transfer notes.

If large files must be shared, use manual copy, external release attachments, object storage, school/server shared directories, or Git LFS after explicit approval. The default project policy does not use Git LFS.

Release packages should not include large public data unless explicitly requested. They should include the manifests and reports needed to recreate or verify the local data layout.
