# nrecon

nrecon is a Common Lisp toolkit for authorized web fuzzing and network reconnaissance. This initial core provides module declarations, dataflow pipelines, pure job and result records, and a pure authorization decision API.

## Core API

To try the examples in a live session, enter the flake development shell, start SBCL, and load the core system:

```sh
nix develop
sbcl
```

At the SBCL prompt, load the system and make its exported API available in the current package:

```lisp
(require "asdf")
(asdf:load-system "nrecon/core")
(use-package "NRECON.CORE")
```

Declare a module with capability and option lists, plus a function symbol for its runner:

```lisp
(define-module http-fuzz
  :capabilities (:http)
  :options (:target :wordlist)
  :run run-http-fuzz)

(find-module 'http-fuzz)
(list-modules)
```

define-module quotes the capability and option lists into the declaration and resolves the :run function symbol when the system loads. Module runners use the signature (input context). find-module returns a module or nil; list-modules returns modules in name order. Module records expose module-name, module-capabilities, module-options, and module-run.

Create a sequential dataflow pipeline with make-cps-pipeline and run it with run-cps-pipeline:

```lisp
(make-cps-pipeline stages)
(run-cps-pipeline pipeline input
                  :context dataflow-context
                  :continuation terminal)
```

Each stage has the signature (input context) and returns a value or a cl-concurrent-kit promise. The terminal continuation has the signature (value context) and also returns a value or promise. The runner builds a cl-dataflow-kit pipeline and chains promise results with promise-then; it does not block while waiting for a stage.

run-cps-pipeline returns a plain value when every stage and the terminal continuation are synchronous. It returns a promise when an asynchronous result flows through the pipeline.

make-job accepts :id, :target, and :options. make-result accepts :job-id, :status (:completed or :failed), :value, and :metadata. These records contain data only.

## Authorization

make-authorization-policy accepts :actions, :allowlist, and :lab-only-p (default t). make-authorization-target accepts :host and an explicit :lab-p marker (default nil). Call authorize-action with a policy, action, and target; it returns an authorization decision with authorization-decision-allowed-p and authorization-decision-reason.

The gate requires a nonempty allowlist and an exact action-scope match, compared case-insensitively. Allowlist entries can be hostnames, domains, or IPv4 CIDRs with prefixes from 0 through 32. A hostname or domain entry matches its exact normalized hostname and label-boundary subdomains; IPv4 address entries match only the exact address. CIDRs compare IPv4 addresses after masking host bits. URLs, ports, IPv6, wildcards, and malformed entries do not match. Lab-only mode requires the target's explicit marker; the marker is a caller assertion, not network discovery. The gate performs no logging or network I/O.

## Checks

Nix with flakes enabled is required to provide the core kit dependencies. Run the tests in that configured environment:

```sh
nix run .#test
nix flake check
```
