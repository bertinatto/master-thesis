MAINFILE = main
LATEXMKFLAGS = -pdf -interaction=batchmode -halt-on-error -shell-escape

.PHONY: all
all:
	latexmk $(LATEXMKFLAGS) $(MAINFILE).tex

.PHONY: watch
watch:
	latexmk $(LATEXMKFLAGS) -pvc $(MAINFILE).tex

.PHONY: clean
clean:
	latexmk -c
	rm -f *.aux *.fls *.log *.nav *.out *.snm *.toc *.vrb *.fdb_latexmk

.PHONY: distclean
distclean:
	latexmk -C
	rm -f *.aux *.fls *.log *.nav *.out *.snm *.toc *.vrb *.fdb_latexmk
	rm -rf build/ auto/
