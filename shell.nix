{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {

  packages = [
	pkgs.openssl
	pkgs.git
	pkgs.python311
	pkgs.pandoc
	pkgs.asciidoctor
  ];

}
