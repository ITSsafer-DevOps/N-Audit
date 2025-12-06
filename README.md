🛡️ N-Audit Ecosystem

Next-Generation Enterprise Security Assessment Platform

N-Audit Ecosystem represents a comprehensive suite of offensive security tools designed to solve the critical challenges of modern penetration testing: Scope Enforcement, Forensic Integrity, and AI Privacy.

The ecosystem consists of two primary components tailored for specific environments:

N-Audit CLI: For local, containerized network assessments (Podman/Docker).

N-Audit Sentinel: For cloud-native, Kubernetes forensic operations (Cilium/K8s).

🌏 Ecosystem Overview

The N-Audit architecture ensures that whether you are testing a legacy network or a microservices cluster, the audit trail is immutable, and the scope is enforced at the kernel level.

graph TB
    %% Styles
    classDef actor fill:#0d1117,stroke:#fff,stroke-width:2px,color:#fff;
    classDef core fill:#00ADD8,stroke:#333,stroke-width:2px,color:#fff;
    classDef cloud fill:#f05133,stroke:#333,stroke-width:2px,color:#fff;
    classDef security fill:#2ea44f,stroke:#333,stroke-width:2px,color:#fff;
    classDef output fill:#6e7681,stroke:#333,stroke-dasharray: 5 5,color:#fff;

    User((👮 Security<br/>Professional)):::actor

    subgraph "Control Plane"
        Config[Scope Definition<br/>.md / .yaml]
        Keys[AI API Keys]
    end

    subgraph "Execution Plane"
        direction LR
        subgraph "Local Assessment"
            CLI[<b>N-Audit CLI</b><br/>Go Binary]:::core
            Podman[Podman Engine]:::core
        end
        
        subgraph "Cloud Forensics"
            Sentinel[<b>N-Audit Sentinel</b><br/>K8s Pod PID 1]:::cloud
            Cilium[Cilium eBPF]:::cloud
        end
    end

    subgraph "Enforcement & Privacy Layer"
        Firewall{Kernel<br/>Firewall}:::security
        Sanitizer{AI Data<br/>Sanitizer}:::security
        Signer{Crypto<br/>Signer}:::security
    end

    subgraph "Output Artifacts"
        Logs[Forensic Logs<br/>SHA256 Signed]:::output
        Report[HTML/PDF<br/>Reports]:::output
    end

    %% Flows
    User -->|Interactive Cmd| CLI
    User -->|kubectl attach| Sentinel
    Config --> CLI & Sentinel
    
    CLI --> Podman
    Podman --> Firewall
    
    Sentinel --> Cilium
    Cilium --> Firewall
    
    CLI & Sentinel --> Sanitizer
    Sanitizer -.->|Anonymized Prompt| CloudAI((☁️ LLM Cloud))
    
    CLI & Sentinel --> Signer
    Signer --> Logs
    Logs --> Report


1. N-Audit CLI (Core)

Target Environment: Local Linux Workstations, Bastion Hosts

Tech Stack: Go 1.24+, Podman, Iptables

N-Audit CLI is a statically compiled binary that wraps standard penetration testing tools in a secure, monitored container environment. It acts as a middleware between the tester and the OS to prevent scope creep and enable safe AI usage.

🔑 Key Features

Kernel-Level Scope Guard: Uses iptables and network namespaces to physically block traffic to out-of-scope targets.

Zero-Knowledge AI: Sanitizes sensitive data (IPs, Domains) before sending prompts to LLMs (Perplexity, Gemini, DeepSeek).

Forensic Replay: Records sessions with SHA256 checksums, allowing for court-admissible playback.

🏗️ Architecture

flowchart TB
    subgraph "User Space (Unprivileged)"
        Input[User Input] --> Parser[Command Parser]
        Parser --> Validator{Scope<br/>Validator}
        
        Validator -- Allowed --> PTY[PTY Wrapper]
        Validator -- Blocked --> AuditLog[Audit Violation]
        
        subgraph "AI Subsystem"
            LogStream[Log Stream] --> PII_Filter[PII Sanitizer]
            PII_Filter --> AI_Client[AI Client]
        end
    end

    subgraph "Container Space (Isolated)"
        PTY -->|Exec| Container[Podman Container<br/>(Kali Linux)]
    end

    subgraph "Kernel Space (Privileged)"
        Container -->|Net Namespace| NetFilter[Netfilter/Iptables]
        NetFilter -- "In Scope" --> Allow((Allow))
        NetFilter -- "Out of Scope" --> Drop((Drop))
    end

    PTY -.-> LogStream
    
    style Validator fill:#2ea44f,color:white
    style NetFilter fill:#bc8cff,color:white
    style PII_Filter fill:#d2a8ff,color:black


2. N-Audit Sentinel

Target Environment: Kubernetes Clusters (K3s, EKS, GKE, AKS)

Tech Stack: Go, Cilium CNI, SSH Signing, PID 1

N-Audit Sentinel is a Kubernetes-native forensic wrapper that runs as PID 1 inside a pod. It brings the discipline of N-Audit to ephemeral cloud environments by leveraging Cilium for Layer 3/4/7 enforcement.

🔑 Key Features

PID 1 Safety Loop: Respawns the shell on accidental exit, ensuring persistence during operations.

Cilium Policy Enforcement: Dynamically generates and applies CiliumNetworkPolicies based on the defined scope.

Cryptographic Seal: At session termination, logs are hashed (SHA-256) and signed with an Ed25519 SSH key.

🏗️ Kubernetes Workflow

graph LR
    subgraph "Forensic Pod Lifecycle"
        Boot[PID 1 Start] --> Discovery[K8s Discovery]
        Discovery --> TUI[Scope TUI]
        
        subgraph "Security Loop"
            TUI --> PolicyGen[Policy Gen]
            PolicyGen -->|Apply CRD| K8sAPI[K8s API]
            K8sAPI -->|Enforce| eBPF[Cilium eBPF]
            
            eBPF --> Shell[Interactive Shell]
            Shell -->|User Cmd| eBPF
            Shell -->|Stream| Logger[Forensic Logger]
        end
        
        subgraph "Teardown & Evidence"
            Signal[Exit Signal] --> Hasher[SHA256 Hash]
            Hasher --> Signer[Ed25519 Sign]
            Signer --> Artifact[Signed Log]
        end
    end
    
    Shell --> Signal
    Logger --> Hasher
    
    style Boot fill:#f05133,color:white
    style eBPF fill:#f9c74f,stroke:#333
    style Artifact fill:#2ea44f,color:white


⚔️ Comparison & Feature Parity

Feature

N-Audit CLI (Desktop)

N-Audit Sentinel (Cloud)

Primary Scope Enforcement

iptables (Linux Kernel)

CiliumNetworkPolicy (eBPF)

Isolation Mechanism

Podman Containers (Rootless)

Kubernetes Pod

Session Persistence

Interactive PTY Wrapper

PID 1 Supervisor Loop

Forensic Integrity

SHA256 Checksums

SHA256 + SSH Signature (Ed25519)

AI Integration

Zero-Knowledge Proxy (Active)

Planned / Roadmap

Deployment

Single Binary (go build)

Container Image / Helm / Terraform

🚀 Getting Started

For Local Testing (N-Audit CLI)

# Build the binary
make build

# Start a session with scope enforcement
sudo ./n-audit session --scope config/scope.md --client "Acme Corp"



For Kubernetes Forensics (Sentinel)

# Deploy to cluster
kubectl apply -f deploy/manifests/

# Attach to the forensic pod
kubectl attach -it n-audit-sentinel -c sentinel



📜 License

MIT License

Copyright (c) 2025

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
