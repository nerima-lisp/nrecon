{
  description = "Core of nrecon, an authorized security testing toolkit";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    cl-nix-forge = {
      url = "github:nerima-lisp/cl-nix-forge/v0.6.1";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    cl-dataflow-kit = {
      url = "github:nerima-lisp/cl-dataflow-kit/v1.2.0";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    cl-concurrent-kit = {
      url = "github:nerima-lisp/cl-concurrent-kit/v0.6.1";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    cl-cli = {
      url = "github:nerima-lisp/cl-cli/v1.4.0";
      flake = false;
    };

    cl-host-kit.follows = "cl-dataflow-kit/cl-host-kit";

    cl-codec-kit = {
      url = "github:nerima-lisp/cl-codec-kit/v0.5.0";
      flake = false;
    };

    cl-date-kit.follows = "cl-concurrent-kit/cl-date-kit";

    cl-boundary-kit = {
      url = "github:nerima-lisp/cl-boundary-kit/v2.3.0";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    cl-deflate-kit = {
      url = "github:nerima-lisp/cl-deflate-kit/v0.4.0";
      flake = false;
    };

    cl-http-kit = {
      url = "github:nerima-lisp/cl-http-kit/v0.4.0";
      flake = false;
    };

    cl-parser-kit = {
      url = "github:nerima-lisp/cl-parser-kit/v1.1.1";
      flake = false;
    };

    cl-log-kit = {
      url = "github:nerima-lisp/cl-log-kit/v2.2.0";
      inputs = {
        nixpkgs.follows = "nixpkgs";
        cl-concurrent-kit.follows = "cl-concurrent-kit";
        cl-date-kit.follows = "cl-concurrent-kit/cl-date-kit";
      };
    };

    cl-weave = {
      url = "github:nerima-lisp/cl-weave/v1.4.0";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    cl-json-kit = {
      url = "github:nerima-lisp/cl-json-kit/v1.0.0";
      flake = false;
    };

    cl-regex-kit = {
      url = "github:nerima-lisp/cl-regex-kit/v2.2.0";
      flake = false;
    };

    cl-resilience-kit = {
      url = "github:nerima-lisp/cl-resilience-kit/v1.0.0";
      flake = false;
    };

    cl-cffi-kit = {
      url = "github:nerima-lisp/cl-cffi-kit";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    cl-pcap-kit = {
      url = "github:nerima-lisp/cl-pcap-kit";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.cl-cffi-kit.follows = "cl-cffi-kit";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      cl-nix-forge,
      cl-dataflow-kit,
      cl-concurrent-kit,
      cl-cli,
      cl-host-kit,
      cl-codec-kit,
      cl-date-kit,
      cl-boundary-kit,
      cl-deflate-kit,
      cl-http-kit,
      cl-parser-kit,
      cl-log-kit,
      cl-weave,
      cl-json-kit,
      cl-regex-kit,
      cl-resilience-kit,
      cl-cffi-kit,
      cl-pcap-kit,
    }:
    let
      systems = [
        "aarch64-darwin"
        "x86_64-linux"
      ];
    in
    cl-nix-forge.lib.${builtins.head systems}.mkPackageFlake {
      inherit self nixpkgs systems;

      pname = "nrecon";
      asd = ./nrecon.asd;
      root = ./.;
      sourceInclude = [ ./src/net/fixtures/discovery.pcap ];
      lispSystem = "nrecon/wire";
      executable = {
        lispSystem = "nrecon/cli/executable";
        programPath = "nrecon";
      };

      lispDependencies =
        ctx:
        let
          forge = cl-nix-forge.lib.${ctx.system};
          codecKit = forge.lispDerivation {
            pname = "cl-codec-kit";
            lispSystem = "cl-codec-kit";
            version = forge.fromAsdSystem "${cl-codec-kit}/cl-codec-kit.asd";
            src = cl-codec-kit;
          };
          deflateKit = forge.lispDerivation {
            pname = "cl-deflate-kit";
            lispSystem = "cl-deflate-kit";
            version = forge.fromAsdSystem "${cl-deflate-kit}/cl-deflate-kit.asd";
            src = cl-deflate-kit;
          };
          parserKit = forge.lispDerivation {
            pname = "cl-parser-kit";
            lispSystem = "cl-parser-kit";
            version = forge.fromAsdSystem "${cl-parser-kit}/cl-parser-kit.asd";
            src = cl-parser-kit;
          };
          httpClient = forge.lispDerivation {
            pname = "cl-http-kit";
            lispSystem = "cl-http-kit/client";
            version = forge.fromAsdSystem "${cl-http-kit}/cl-http-kit.asd";
            src = cl-http-kit;
            lispDependencies = [
              codecKit
              deflateKit
            ];
          };
          regexKit = forge.lispDerivation {
            pname = "cl-regex-kit";
            lispSystem = "cl-regex-kit";
            version = forge.fromAsdSystem "${cl-regex-kit}/cl-regex-kit.asd";
            src = cl-regex-kit;
            lispDependencies = [
              parserKit
              cl-concurrent-kit.packages.${ctx.system}.cl-concurrent-kit
            ];
          };
          resilienceKit = forge.lispDerivation {
            pname = "cl-resilience-kit";
            lispSystem = "cl-resilience-kit";
            version = forge.fromAsdSystem "${cl-resilience-kit}/cl-resilience-kit.asd";
            src = cl-resilience-kit;
            lispDependencies = [
              cl-boundary-kit.packages.${ctx.system}.cl-boundary-kit
              cl-concurrent-kit.packages.${ctx.system}.cl-concurrent-kit
            ];
          };
          jsonKit = ctx.cl.fromNixpkgsLisp {
            drv = ctx.pkgs.sbcl.buildASDFSystem {
              pname = "cl-json-kit";
              version = "1.0.0";
              src = cl-json-kit;
              systems = [ "cl-json-kit" ];
            };
            lispImplementation = "sbcl";
          };
          hostKit = forge.lispDerivation {
            lispSystem = "cl-host-kit";
            version = forge.fromAsdSystem "${cl-host-kit}/cl-host-kit.asd";
            src = cl-host-kit;
          };
          cliKit = forge.lispDerivation {
            lispSystem = "cl-cli";
            version = forge.fromAsdSystem "${cl-cli}/cl-cli.asd";
            src = cl-cli;
            lispDependencies = [ hostKit ];
          };
        in
        [
          cl-dataflow-kit.packages.${ctx.system}.default
          cl-concurrent-kit.packages.${ctx.system}.cl-concurrent-kit
          cliKit
          cl-date-kit.packages.${ctx.system}.cl-date-kit
          cl-boundary-kit.packages.${ctx.system}.cl-boundary-kit
          cl-log-kit.packages.${ctx.system}.cl-log-kit
          cl-cffi-kit.packages.${ctx.system}.cl-cffi-kit
          cl-pcap-kit.packages.${ctx.system}.cl-pcap-kit
          codecKit
          httpClient
          regexKit
          resilienceKit
          jsonKit
        ];

      lispCheckDependencies = ctx: [
        cl-weave.packages.${ctx.system}.cl-weave
      ];

      packageArgs = ctx: {
        nativeLibraries = [ ctx.pkgs.libpcap ];
      };

      meta = {
        description = "Core of nrecon, an authorized security testing toolkit";
        license = nixpkgs.lib.licenses.mit;
        platforms = nixpkgs.lib.platforms.unix;
      };
    };
}
