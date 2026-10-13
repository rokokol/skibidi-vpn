{
  description = "Deploy and maintain the 3x-ui VPN nodes";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    # The letters' theme comes from the themes repo the same way mail-node's
    # does: locked here, updated by `nix flake update`, copied nowhere. The
    # letter file is generated from one palette revision inside that repo, so
    # the digest and the alert mail agree with each other by construction
    ddlc-themes = {
      url = "github:rokokol/ddlc-themes";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      nixpkgs,
      ddlc-themes,
      # The caller always passes self, so a list without `...` has to name it, and naming
      # what nothing reads is what deadnix objects to. `...` accepts it and reads nothing
      ...
    }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAll = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});

      # Each piece isolated, so an edit to a role or a document rebuilds nothing
      noSecrets = builtins.path {
        name = "no-secrets.sh";
        path = ./tests/no-secrets.sh;
      };
      falsifySecrets = builtins.path {
        name = "falsify-secrets.sh";
        path = ./tests/falsify-secrets.sh;
      };
      # The defect list t.sh falsify sources; t.sh itself is vendored and checked at its source
      defects = builtins.path {
        name = "defects.sh";
        path = ./tests/defects.sh;
      };
    in
    {
      devShells = forAll (pkgs: {
        default = pkgs.mkShell {
          packages = with pkgs; [
            ansible
            ansible-lint
            yamllint
            python3
            # Molecule drives the VM tests; libvirt and QEMU are what it drives.
            # The nodes are Ubuntu, so a container would not exercise systemd,
            # the firewall or the tunnel — the three things worth testing
            (python3.withPackages (
              ps: with ps; [
                molecule
                molecule-plugins
              ]
            ))
            qemu
            libvirt
            # A cloud image plus a seed ISO is the whole VM: cloud-utils builds
            # the seed, xorriso is what it shells out to. vagrant is deliberately
            # absent - its libvirt provider is a plugin nixpkgs does not carry,
            # so the scenario drives QEMU directly instead
            cloud-utils
            xorriso
            curl
            openssh
            shellcheck
          ];

          # Deploys run from this shell, and the roles read this to carry the
          # theme onto the nodes — the letter file the HTML takes its colours,
          # faces and styles from, riding the lockfile, never a copy in a
          # tracked file
          SKIBIDI_MAIL = "${ddlc-themes.lib.mail}";

          shellHook = ''
            export SKIBIDI_NODES_DIR="''${SKIBIDI_NODES_DIR:-$PWD/inventory/nodes}"
            echo "nodes: $SKIBIDI_NODES_DIR"
          '';
        };

        # What a push gate needs and nothing it does not: the default shell's
        # QEMU/libvirt closure would make every CI run pay for the VM tests
        # that only the manual molecule workflow actually runs
        ci = pkgs.mkShell {
          packages = with pkgs; [
            ansible
            ansible-lint
            yamllint
            # jinja2 because the templates' promises are themselves under test
            (python3.withPackages (ps: with ps; [ jinja2 ]))
            # The backup tests stage real SQLite stores through the rendered
            # script, push them with a real restic to a real rest-server, and
            # hold the script to shellcheck
            sqlite
            shellcheck
            restic
            restic-rest-server
          ];
          SKIBIDI_MAIL = "${ddlc-themes.lib.mail}";
        };
      });

      checks = forAll (pkgs: {
        # Everything that needs no network and no VM, so it can gate a push.
        # The scripts isolated rather than reached for through ${self}: that ties the check
        # to the whole repository, so every commit gives it a new hash and rebuilds it
        lint = pkgs.runCommand "skibidi-vpn-lint" { buildInputs = with pkgs; [ shellcheck ]; } ''
          shellcheck ${noSecrets} ${falsifySecrets} ${defects}
          touch $out
        '';
      });

      # Without this output `nix fmt` does nothing here and a gate has nothing to run
      formatter = forAll (pkgs: pkgs.nixfmt-tree);
    };
}
