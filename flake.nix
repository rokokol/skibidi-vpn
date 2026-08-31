{
  description = "Deploy and maintain the 3x-ui VPN nodes";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
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

          shellHook = ''
            export SKIBIDI_NODES_DIR="''${SKIBIDI_NODES_DIR:-$PWD/inventory/nodes}"
            echo "nodes: $SKIBIDI_NODES_DIR"
          '';
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
