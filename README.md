🛡️ N-Audit Ecosystem

Next-Generation Enterprise Security Assessment Platform

N-Audit Ecosystem represents a comprehensive suite of offensive security tools designed to solve the critical challenges of modern penetration testing: Scope Enforcement, Forensic Integrity, and AI Privacy.

The ecosystem consists of two primary components tailored for specific environments:

N-Audit CLI: For local, containerized network assessments (Podman/Docker).

N-Audit Sentinel: For cloud-native, Kubernetes forensic operations (Cilium/K8s).

🌏 Ecosystem Overview

The N-Audit architecture ensures that whether you are testing a legacy network or a microservices cluster, the audit trail is immutable, and the scope is enforced at the kernel level.

graph TD
    User((Security Professional))
    
    subgraph "Local / Network Operations"
        NAudit["<b>N-Audit CLI</b><br/>Go Binary + Podman"]
        Scope1[Iptables Scope Guard]
        AI[Zero-Knowledge AI Proxy]
    end
    
    subgraph "Cloud / Kubernetes Operations"
        Sentinel["<b>N-Audit Sentinel</b><br/>K8s Pod (PID 1)"]
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


1. N-Audit CLI (Core)

Target Environment: Local Linux Workstations, Bastion Hosts

Tech Stack: Go 1.24+, Podman, Iptables

N-Audit CLI is a statically compiled binary that wraps standard penetration testing tools in a secure, monitored container environment. It acts as a middleware between the tester and the OS to prevent scope creep and enable safe AI usage.

🔑 Key Features

Kernel-Level Scope Guard: Uses iptables and network namespaces to physically block traffic to out-of-scope targets.

Zero-Knowledge AI: Sanitizes sensitive data (IPs, Domains) before sending prompts to LLMs (Perplexity, Gemini, DeepSeek).

Forensic Replay: Records sessions with SHA256 checksums, allowing for court-admissible playback.

🏗️ Architecture

flowchart LR
    Tester[Tester Input] -->|Command| Parser[Command Parser]
    
    subgraph "N-Audit Core"
        Parser -->|Check Scope| Validator{Scope Validator}
        Validator -- Allowed --> PTY[PTY Session]
        Validator -- Blocked --> Reject[Log Violation]
        
        PTY -->|Execution| Podman[Podman Container]
        PTY -->|Stream| Logger[Forensic Logger]
        
        subgraph "AI Layer"
            Logger --> Sanitizer[Data Sanitizer]
            Sanitizer --> AI_API[External AI Provider]
        end
    end
    
    Podman -->|Network| Kernel[Linux Kernel / Iptables]
    Kernel --> Target((Target Network))


2. N-Audit Sentinel

Target Environment: Kubernetes Clusters (K3s, EKS, GKE, AKS)

Tech Stack: Go, Cilium CNI, SSH Signing, PID 1

N-Audit Sentinel is a Kubernetes-native forensic wrapper that runs as PID 1 inside a pod. It brings the discipline of N-Audit to ephemeral cloud environments by leveraging Cilium for Layer 3/4/7 enforcement.

🔑 Key Features

PID 1 Safety Loop: Respawns the shell on accidental exit, ensuring persistence during operations.

Cilium Policy Enforcement: Dynamically generates and applies CiliumNetworkPolicies based on the defined scope.

Cryptographic Seal: At session termination, logs are hashed (SHA-256) and signed with an Ed25519 SSH key.

🏗️ Kubernetes Workflow

flowchart LR
  subgraph Kubernetes Cluster
    Pod([N-Audit Sentinel Pod])
    Vol[(hostPath Storage)]
    API[(K8s API)]
    DNS[(CoreDNS)]
    CNP[[CiliumNetworkPolicy]]
  end

  User[Operator] -->|kubectl attach| Pod
  Pod -->|Discover| API
  Pod -->|Resolve| DNS
  Pod -.->|Enforce Scope| CNP
  Pod <-->|Audit Logs| Vol
  
  style Pod fill:#f05133,color:white
  style CNP fill:#f9c74f,stroke:#333


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
