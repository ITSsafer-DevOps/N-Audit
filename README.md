# 🛡️ N-Audit Ecosystem
### Next-Generation Enterprise Security Assessment Platform

**N-Audit Ecosystem** represents a comprehensive suite of offensive security tools designed to solve the critical challenges of modern penetration testing: **Scope Enforcement**, **Forensic Integrity**, and **AI Privacy**.

The ecosystem consists of two primary components tailored for specific environments:
1.  **N-Audit CLI:** For local, containerized network assessments (Podman/Docker).
2.  **N-Audit Sentinel:** For cloud-native, Kubernetes forensic operations (Cilium/K8s).

---

## 🌏 Ecosystem Overview

The N-Audit architecture ensures that whether you are testing a legacy network or a microservices cluster, the audit trail is immutable, and the scope is enforced at the kernel level.

```mermaid
graph TD
    User((Security Professional))
    
    subgraph "Local / Network Operations"
        NAudit[<b>N-Audit CLI</b><br/>Go Binary + Podman]
        Scope1[Iptables Scope Guard]
        AI[Zero-Knowledge AI Proxy]
    end
    
    subgraph "Cloud / Kubernetes Operations"
        Sentinel[<b>N-Audit Sentinel</b><br/>K8s Pod (PID 1)]
        Cilium[Cilium Network Policy]
        Seal[Cryptographic Seal]
    end

    User -->|Interactive Session| NAudit
    User -->|Attach PTY| Sentinel
    
    NAudit -->|Enforces| Scope1
    NAudit -->|Sanitizes| AI
    
    Sentinel -->|Enforces| Cilium
    Sentinel -->|Signs| Seal
    
    style NAudit fill:#00ADD8,stroke:#333,stroke-width:2px,color:white
    style Sentinel fill:#f05133,stroke:#333,stroke-width:2px,color:white
