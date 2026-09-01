{
  description = "Deploy and maintain the 3x-ui VPN nodes";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    # The report's theme comes from the themes repo the same way mail-node's
    # does: locked here, updated by `nix flake update`, copied nowhere. One
    # input on purpose - the charts' mplstyle and the HTML's stylesheet are
    # generated from one palette revision inside that repo, so consuming both
    # from it makes the letter agree with itself by construction
    ddlc-themes = {
      url = "github:rokokol/ddlc-themes";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    { self, nixpkgs, ddlc-themes }:
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

          # Deploys run from this shell, and the roles read these to carry the
          # theme onto the nodes — the matplotlib style for the charts and the
          # report stylesheet the HTML inlines its colours from, both riding
          # the lockfile, never a copy in a tracked file
          SKIBIDI_MPLSTYLE = "${ddlc-themes.lib.matplotlib.light}";
          SKIBIDI_REPORT_CSS = "${ddlc-themes.lib.report}";
          # Transitional: until the locked theme revision exports the critical
          # variables itself, the character names ride along from the palette the
          # theme was built from — reached through its graph, never a second pin
          SKIBIDI_PALETTE_JSON = builtins.toJSON ddlc-themes.inputs.ddlc-palette.lib.palette;
          # The charts' text face, deployed to the master so matplotlib there
          # letters its axes the way the tables around it are set
          SKIBIDI_CHART_FONT = "${pkgs.departure-mono}/share/fonts/otf/DepartureMono-Regular.otf";

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
          SKIBIDI_MPLSTYLE = "${ddlc-themes.lib.matplotlib.light}";
          SKIBIDI_REPORT_CSS = "${ddlc-themes.lib.report}";
          # Transitional: until the locked theme revision exports the critical
          # variables itself, the character names ride along from the palette the
          # theme was built from — reached through its graph, never a second pin
          SKIBIDI_PALETTE_JSON = builtins.toJSON ddlc-themes.inputs.ddlc-palette.lib.palette;
          SKIBIDI_CHART_FONT = "${pkgs.departure-mono}/share/fonts/otf/DepartureMono-Regular.otf";
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
