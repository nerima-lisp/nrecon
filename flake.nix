{
  description = "Core of nrecon, an authorized security testing toolkit";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    cl-nix-forge = {
      url = "github:nerima-lisp/cl-nix-forge/v0.5.0";
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

    cl-date-kit.follows = "cl-concurrent-kit/cl-date-kit";

    cl-boundary-kit = {
      url = "github:nerima-lisp/cl-boundary-kit/v2.3.0";
      inputs.nixpkgs.follows = "nixpkgs";
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
  };

  outputs =
    {
      self,
      nixpkgs,
      cl-nix-forge,
      cl-dataflow-kit,
      cl-concurrent-kit,
      cl-date-kit,
      cl-boundary-kit,
      cl-log-kit,
      cl-weave,
      cl-json-kit,
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
      lispSystem = "nrecon/wire";

      lispDependencies = ctx: [
        cl-dataflow-kit.packages.${ctx.system}.default
        cl-concurrent-kit.packages.${ctx.system}.cl-concurrent-kit
        cl-date-kit.packages.${ctx.system}.cl-date-kit
        cl-boundary-kit.packages.${ctx.system}.cl-boundary-kit
        cl-log-kit.packages.${ctx.system}.cl-log-kit
          (ctx.cl.fromNixpkgsLisp {
            drv = ctx.pkgs.sbcl.buildASDFSystem {
              pname = "cl-json-kit";
              version = "1.0.0";
              src = cl-json-kit;
              systems = [ "cl-json-kit" ];
            };
            lispImplementation = "sbcl";
          })
      ];

      lispCheckDependencies = ctx: [
        cl-weave.packages.${ctx.system}.cl-weave
      ];

      meta = {
        description = "Core of nrecon, an authorized security testing toolkit";
        license = nixpkgs.lib.licenses.mit;
        platforms = nixpkgs.lib.platforms.unix;
      };
    };
}
