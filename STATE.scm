;;; STATE.scm — Project Wharf Checkpoint
;;; SPDX-License-Identifier: MIT
;;; Author: Jonathan D. A. Jewell (@hyperpolymath)
;;;
;;; Checkpoint/restore system for AI conversation continuity.
;;; Load with: guile -c '(load "STATE.scm")'

(define state
  '(

    ;;; =========================================================================
    ;;; METADATA
    ;;; =========================================================================
    (metadata
     (format-version . "1.0")
     (schema-version . "2025-12-08")
     (created-at . "2025-12-08T00:00:00Z")
     (last-updated . "2025-12-08T00:00:00Z")
     (generator . "claude-opus-4-5"))

    ;;; =========================================================================
    ;;; USER CONTEXT
    ;;; =========================================================================
    (user
     (name . "hyperpolymath")
     (roles . ("core-maintainer" "architect" "security-engineer"))
     (preferences
      (languages . ("rust" "nickel" "scheme" "bash"))
      (tools . ("cargo" "just" "podman" "nebula" "guix"))
      (values . ("security-first" "zero-trust" "reversibility" "offline-administration"))))

    ;;; =========================================================================
    ;;; SESSION CONTEXT
    ;;; =========================================================================
    (session
     (conversation-id . "wharf-mvp-planning-2025-12-08")
     (started-at . "2025-12-08T00:00:00Z")
     (checkpoint-reason . "initial-state-documentation"))

    ;;; =========================================================================
    ;;; CURRENT FOCUS
    ;;; =========================================================================
    (focus
     (current-project . "wharf-mvp-v1")
     (current-phase . "integration-and-testing")
     (deadline . #f)
     (blocking-projects . ("ebpf-toolchain" "container-builds")))

    ;;; =========================================================================
    ;;; CURRENT POSITION — Where We Are Now
    ;;; =========================================================================
    (current-position
     (version . "0.1.0-dev")
     (maturity . "early-development")
     (summary . "Foundation complete with core security architecture implemented.
                 Database proxy, file integrity, and CMS adapters exist but need
                 integration testing and production hardening.")

     (completed-components
      ("wharf-core library with SQL AST parsing and BLAKE3 integrity")
      ("wharf-cli with init/build/moor/state/sec subcommands")
      ("yacht-agent runtime with database proxy and header airlock")
      ("WordPress db.php drop-in adapter")
      ("Nebula mesh networking configuration")
      ("DNS zone templates (simple/shared/standard/maximalist)")
      ("Nickel configuration schemas for policies")
      ("eBPF XDP firewall loader with nftables fallback")
      ("FIDO2/WebAuthn authentication framework")
      ("Comprehensive documentation (README, SECURITY, ARCHITECTURE)"))

     (partial-components
      ("Container Dockerfiles exist but not fully tested")
      ("Database policy engine needs real-world validation")
      ("Prometheus metrics are placeholder stubs")
      ("Other CMS adapters (Drupal, Joomla, Moodle) are scaffolded only"))

     (missing-components
      ("Integration test suite")
      ("End-to-end deployment testing")
      ("Production container images")
      ("Monitoring dashboards")
      ("Operational runbooks")))

    ;;; =========================================================================
    ;;; ROUTE TO MVP v1.0 — The Path Forward
    ;;; =========================================================================
    (mvp-route
     (target-version . "1.0.0")
     (definition . "Secure, production-ready WordPress hosting with offline
                    administration via Wharf and read-only Yacht runtime.")

     (milestones
      ((name . "M1: Core Integration")
       (status . "in-progress")
       (completion . 70)
       (tasks
        ("Finalize database proxy with real MySQL/MariaDB testing")
        ("Verify BLAKE3 integrity checks in production scenarios")
        ("Complete rsync/SSH mooring workflow end-to-end")
        ("Test FIDO2 hardware key authentication flow")))

      ((name . "M2: Container Production")
       (status . "pending")
       (completion . 30)
       (tasks
        ("Build and test yacht-agent distroless container")
        ("Build PHP/OpenLiteSpeed container with WordPress")
        ("Validate podman pod deployment (yacht.yaml)")
        ("Create container registry workflow")))

      ((name . "M3: Security Hardening")
       (status . "pending")
       (completion . 40)
       (tasks
        ("Validate eBPF XDP firewall in production kernel")
        ("Test nftables fallback path")
        ("Security audit of database proxy SQL filtering")
        ("Fuzz testing for SQL injection bypass attempts")
        ("Header airlock validation against OWASP headers")))

      ((name . "M4: WordPress Production")
       (status . "pending")
       (completion . 50)
       (tasks
        ("Test db.php drop-in with real WordPress installation")
        ("Verify wp-admin blocking (Dark Matter pattern)")
        ("Test plugin/theme read-only enforcement")
        ("Validate file integrity monitoring with WordPress updates")))

      ((name . "M5: Observability")
       (status . "pending")
       (completion . 10)
       (tasks
        ("Implement real Prometheus metrics (not stubs)")
        ("Create Grafana dashboard for yacht monitoring")
        ("Structured JSON logging throughout")
        ("Health check endpoints for container orchestration")))

      ((name . "M6: Documentation & Release")
       (status . "pending")
       (completion . 20)
       (tasks
        ("Operational deployment guide")
        ("Troubleshooting runbook")
        ("Quick-start tutorial")
        ("Security model documentation")
        ("Release packaging and versioning")))))

    ;;; =========================================================================
    ;;; ISSUES & BLOCKERS
    ;;; =========================================================================
    (issues
     (critical
      ((id . "ISSUE-001")
       (title . "eBPF build requires special toolchain")
       (description . "Building wharf-ebpf requires nightly Rust and bpf-linker.
                       This is fragile and may break with Rust updates.")
       (impact . "Blocks M3: Security Hardening for eBPF path")
       (workaround . "Use nftables fallback mode"))

      ((id . "ISSUE-002")
       (title . "No integration test suite")
       (description . "Unit tests exist but no end-to-end integration tests.
                       Cannot verify full mooring workflow works.")
       (impact . "Risk of regressions, blocks confident v1.0 release")))

     (high
      ((id . "ISSUE-003")
       (title . "Database proxy untested with real CMS load")
       (description . "SQL AST parser works in isolation but hasn't been
                       stress-tested with real WordPress query patterns.")
       (impact . "May have edge cases that break WordPress functionality"))

      ((id . "ISSUE-004")
       (title . "Container images not automated")
       (description . "Dockerfiles exist but no CI/CD pipeline builds and
                       pushes images automatically.")
       (impact . "Manual build process, inconsistent images")))

     (medium
      ((id . "ISSUE-005")
       (title . "Prometheus metrics are stubs")
       (description . "Metrics endpoints return placeholder data, not real
                       instrumentation.")
       (impact . "No production observability"))

      ((id . "ISSUE-006")
       (title . "Only WordPress adapter is production-ready")
       (description . "Drupal, Joomla, Moodle adapters are scaffolded but
                       not tested or validated.")
       (impact . "Limits initial CMS support to WordPress only"))

      ((id . "ISSUE-007")
       (title . "No automated backup/restore testing")
       (description . "Reversibility framework exists but hasn't been
                       tested with real disaster recovery scenarios.")
       (impact . "Cannot guarantee data recovery"))))

    ;;; =========================================================================
    ;;; QUESTIONS FOR USER
    ;;; =========================================================================
    (questions
     (architecture
      ("Q1: Should MVP target Docker or Podman as primary container runtime?")
      ("Q2: Is Kubernetes support required for v1.0 or can it wait for v1.2?")
      ("Q3: What's the target Linux kernel version? (affects eBPF vs nftables default)"))

     (scope
      ("Q4: Is WordPress-only acceptable for MVP, or must other CMSs work?")
      ("Q5: Should multi-site (multiple WordPress per yacht) be in v1.0 or v1.2?")
      ("Q6: What's the priority: self-hosted or managed platform first?"))

     (security
      ("Q7: Is FIDO2 hardware key mandatory or should password auth be fallback?")
      ("Q8: What compliance frameworks matter? (SOC2, GDPR, HIPAA)")
      ("Q9: Should the Dark Matter pattern block wp-admin at nginx or eBPF level?"))

     (operations
      ("Q10: What CI/CD platform? (GitLab CI exists, want GitHub Actions too?)")
      ("Q11: Preferred container registry? (Docker Hub, GitHub, self-hosted)")
      ("Q12: What monitoring stack? (Prometheus+Grafana assumed, alternatives?)"))

     (community
      ("Q13: What's the timeline pressure? Is there a launch event or deadline?")
      ("Q14: Are there beta testers lined up for early validation?")
      ("Q15: Priority for contribution onboarding vs solo development?")))

    ;;; =========================================================================
    ;;; PROJECT CATALOG
    ;;; =========================================================================
    (projects
     ;; Core Components
     ((name . "wharf-core")
      (status . "in-progress")
      (completion . 75)
      (category . "library")
      (phase . "stabilization")
      (dependencies . ())
      (blockers . ())
      (next . ("Add comprehensive unit tests" "Document public API")))

     ((name . "wharf-cli")
      (status . "in-progress")
      (completion . 70)
      (category . "binary")
      (phase . "feature-complete")
      (dependencies . ("wharf-core"))
      (blockers . ())
      (next . ("Integration tests" "Error message improvements")))

     ((name . "yacht-agent")
      (status . "in-progress")
      (completion . 65)
      (category . "binary")
      (phase . "integration")
      (dependencies . ("wharf-core"))
      (blockers . ("real-world database proxy testing"))
      (next . ("MySQL stress testing" "Implement real metrics")))

     ((name . "wharf-ebpf")
      (status . "blocked")
      (completion . 40)
      (category . "kernel-module")
      (phase . "development")
      (dependencies . ())
      (blockers . ("requires nightly rust" "bpf-linker toolchain fragile"))
      (next . ("Stabilize build process" "Test on production kernels")))

     ;; Infrastructure
     ((name . "container-images")
      (status . "in-progress")
      (completion . 30)
      (category . "infrastructure")
      (phase . "development")
      (dependencies . ("yacht-agent"))
      (blockers . ("no CI/CD automation"))
      (next . ("Test distroless builds" "Create registry workflow")))

     ((name . "nebula-mesh")
      (status . "in-progress")
      (completion . 60)
      (category . "infrastructure")
      (phase . "integration")
      (dependencies . ())
      (blockers . ())
      (next . ("End-to-end connectivity testing" "Certificate rotation testing")))

     ;; CMS Adapters
     ((name . "wordpress-adapter")
      (status . "in-progress")
      (completion . 70)
      (category . "adapter")
      (phase . "testing")
      (dependencies . ("yacht-agent"))
      (blockers . ())
      (next . ("Production WordPress testing" "Plugin compatibility matrix")))

     ((name . "drupal-adapter")
      (status . "paused")
      (completion . 15)
      (category . "adapter")
      (phase . "scaffolding")
      (dependencies . ("wordpress-adapter"))
      (blockers . ("wordpress-adapter must be stable first"))
      (next . ("Defer until post-MVP")))

     ;; Observability
     ((name . "monitoring-stack")
      (status . "pending")
      (completion . 10)
      (category . "observability")
      (phase . "planning")
      (dependencies . ("yacht-agent"))
      (blockers . ())
      (next . ("Implement real Prometheus metrics" "Create Grafana dashboards")))

     ;; Documentation
     ((name . "operational-docs")
      (status . "pending")
      (completion . 20)
      (category . "documentation")
      (phase . "planning")
      (dependencies . ("wharf-cli" "yacht-agent"))
      (blockers . ("need stable workflows to document"))
      (next . ("Deployment guide" "Troubleshooting runbook"))))

    ;;; =========================================================================
    ;;; LONG-TERM ROADMAP
    ;;; =========================================================================
    (roadmap
     ((version . "1.0")
      (codename . "MVP")
      (theme . "Secure WordPress Hosting")
      (status . "in-progress")
      (features
       ("Offline Wharf controller with FIDO2")
       ("Read-only Yacht runtime")
       ("Database proxy with SQL AST filtering")
       ("File integrity via BLAKE3")
       ("Nebula mesh networking")
       ("eBPF/nftables firewall")
       ("WordPress production support")
       ("Basic monitoring")))

     ((version . "1.1")
      (codename . "Observatory")
      (theme . "Observability & Reliability")
      (status . "planned")
      (features
       ("Grafana dashboard templates")
       ("Alertmanager integration")
       ("Structured JSON logging")
       ("Log aggregation (Loki/ELK)")
       ("SSL certificate monitoring")
       ("Backup verification")
       ("Disaster recovery testing")))

     ((version . "1.2")
      (codename . "Fleet")
      (theme . "Multi-tenancy & Scale")
      (status . "planned")
      (features
       ("Multiple WordPress sites per yacht")
       ("Site isolation with namespaces")
       ("Resource quotas (CPU, memory, I/O)")
       ("Terraform provisioning modules")
       ("Load balancer integration")
       ("CDN integration (Cloudflare, Fastly)")
       ("Rolling updates with zero downtime")))

     ((version . "2.0")
      (codename . "Graphene")
      (theme . "Graph Intelligence")
      (status . "future")
      (features
       ("ArangoDB as MySQL alternative")
       ("Graph-based security analysis")
       ("Attack pattern detection")
       ("Anomaly detection ML")
       ("WP-Arango plugin")))

     ((version . "2.1")
      (codename . "Crew")
      (theme . "Team Collaboration")
      (status . "future")
      (features
       ("Role-Based Access Control (RBAC)")
       ("Multi-operator SSH key management")
       ("SSO integration (OIDC, SAML)")
       ("Change approval workflows")
       ("Content staging/preview")
       ("Team notifications (Slack, Discord)")))

     ((version . "2.2")
      (codename . "Intelligence")
      (theme . "Content Intelligence")
      (status . "future")
      (features
       ("AI-assisted content analysis")
       ("SEO integration")
       ("Broken link detection")
       ("Image optimization")
       ("Accessibility audits")
       ("Security scanning (secrets, malware)")))

     ((version . "3.0")
      (codename . "Platform")
      (theme . "Managed Service")
      (status . "future")
      (features
       ("Web dashboard for fleet management")
       ("Self-service site provisioning")
       ("Customer portal")
       ("Third-party API")
       ("Billing and metering")
       ("White-label support")
       ("Compliance reporting (SOC2, GDPR, HIPAA)"))))

    ;;; =========================================================================
    ;;; CRITICAL NEXT ACTIONS
    ;;; =========================================================================
    (critical-next
     ("Set up integration test framework with real MySQL and WordPress")
     ("Validate database proxy with WordPress query patterns under load")
     ("Build and test yacht-agent distroless container image")
     ("Create end-to-end mooring workflow test (wharf -> yacht)")
     ("Implement real Prometheus metrics (replace stubs)")
     ("Write deployment quick-start guide")
     ("Answer architecture questions to finalize MVP scope"))

    ;;; =========================================================================
    ;;; VELOCITY & HISTORY
    ;;; =========================================================================
    (history
     (checkpoints
      ((date . "2025-12-08")
       (event . "Initial STATE.scm creation")
       (overall-completion . 45)
       (notes . "Foundation complete, integration phase beginning"))))

    )) ;; end state

;;; =========================================================================
;;; QUERY HELPERS
;;; =========================================================================

(define (get-section name)
  "Retrieve a section from state by name."
  (assoc name (cdr state)))

(define (display-focus)
  "Show current focus."
  (let ((focus (get-section 'focus)))
    (display "Current Focus:\n")
    (display "  Project: ") (display (cdr (assoc 'current-project (cdr focus)))) (newline)
    (display "  Phase: ") (display (cdr (assoc 'current-phase (cdr focus)))) (newline)))

(define (display-critical-next)
  "Show critical next actions."
  (let ((actions (cdr (get-section 'critical-next))))
    (display "Critical Next Actions:\n")
    (for-each (lambda (action)
                (display "  - ")
                (display action)
                (newline))
              actions)))

(define (display-questions)
  "Show questions requiring answers."
  (let ((questions (cdr (get-section 'questions))))
    (display "Questions for User:\n")
    (for-each (lambda (category)
                (display "\n")
                (display (car category))
                (display ":\n")
                (for-each (lambda (q)
                            (display "  ")
                            (display q)
                            (newline))
                          (cdr category)))
              questions)))

;;; EOF
