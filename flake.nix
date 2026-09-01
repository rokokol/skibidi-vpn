{
  description = "Deploy and maintain the 3x-ui VPN nodes";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    # The report's colours come from the palette repo the same way mail-node's
    # do: locked here, updated by `nix flake update`, copied nowhere
    ddlc-palette = {
      url = "github:rokokol/ddlc-palette";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    { self, nixpkgs, ddlc-palette }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAll = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
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

          # Deploys run from this shell, and the reporter role reads this to
          # carry the theme onto the master — the palette rides the lockfile,
          # never a copy in a tracked file
          SKIBIDI_PALETTE_JSON = builtins.toJSON ddlc-palette.lib.palette;

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
            # matplotlib because the report tests render real charts; the cid
            # round trip proves nothing if no chart was ever attached
            (python3.withPackages (ps: with ps; [ matplotlib ]))
          ];
          SKIBIDI_PALETTE_JSON = builtins.toJSON ddlc-palette.lib.palette;
        };
      });

      checks = forAll (pkgs: {
        # Everything that needs no network and no VM, so it can gate a push
        lint = pkgs.runCommand "skibidi-vpn-lint" { buildInputs = [ pkgs.shellcheck ]; } ''
          shellcheck ${self}/tests/no-secrets.sh
          touch $out
        '';
      });
    };
}
