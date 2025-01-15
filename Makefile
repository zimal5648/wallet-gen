default:
	dune build --profile release

generate:
	dune exec --profile release ./bin/main.exe

verify:
	dune exec --profile release ./bin/verify.exe

clean:
	dune clean
