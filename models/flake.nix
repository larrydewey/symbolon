{
  description = "Symbolon formal models (SPEC Section 27): pinned prover toolchain";

  # Pinned so that a lemma's status depends on the model, not on a tool upgrade.
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/8edc0c72e3a38faf5434e40d1f19431125fe4b30";

  outputs = { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};
    in {
      devShells.${system}.default = pkgs.mkShell {
        packages = [
          pkgs.tamarin-prover # 1.12.0
          pkgs.maude          # 3.5.1
          pkgs.proverif       # 2.05
          pkgs.cryptoverif    # 2.12
          pkgs.easycrypt      # 2026.09
          pkgs.why3           # EasyCrypt SMT bridge
          pkgs.z3
          pkgs.cvc5
        ];
      };
    };
}
